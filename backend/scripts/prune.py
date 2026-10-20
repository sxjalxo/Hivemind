"""Retention, run by an operator -- never on a timer (checklist item 23).

    docker compose --profile tools run --rm prune --older-than 90d          # dry run
    docker compose --profile tools run --rm prune --older-than 90d --apply  # delete

Captured attacker telemetry is the research data, so nothing here deletes
unattended and nothing deletes without a dry run first. Three things grow
without bound once a honeypot faces the internet, and each has its own rule:

* **Elasticsearch indices.** A rolled-over backing index whose newest event is
  older than the cutoff is dropped WHOLE -- unless it holds an event that
  Postgres still points at: evidence an analysis or evaluation cites, or any
  event of a session that has an analysis, a report, an annotation or an
  indicator. Deleting those would leave claims citing events that no longer
  exist. The write index is never dropped. Individual events are never
  deleted (a delete-by-query on a live index is the slow, partial version of
  the same decision).
* **Rotated raw logs** (`cowrie.json.YYYY-MM-DD`, `webpot.json.YYYY-MM-DD`)
  older than the cutoff. They are the copy Filebeat already shipped; the live
  file is never touched.
* **TTY recordings** older than the cutoff, unless a referenced session's
  `cowrie.log.closed` names one. That includes the live honeypot's copies in
  `wild-tty`; the VM keeps its own for 90 days (infra/wild-vm/guard.sh), so one
  pruned younger than that is copied home again by the next pull.

Postgres is not pruned: analyses, evaluations and reports are small, and they
are the record of what this system concluded.
"""

import argparse
import asyncio
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import text

from app.config import get_settings
from app.db.session import get_session_factory
from app.es.client import get_es

_ROTATED = re.compile(r"\.json\.(\d{4}-\d{2}-\d{2})$")
_SHA256 = re.compile(r"[0-9a-f]{64}")

# Every column through which Postgres points at a session or an event.
_SESSION_REFS = (
    "select session_id from analyses",
    "select session_id from reports",
    "select session_id from session_annotations",
    "select session_id from indicator_sessions",
    "select session_id from evidence_refs",
)
_EVENT_REFS = (
    "select es_event_id from evidence_refs",
    "select es_event_id from evaluation_evidence where es_event_id is not null",
    "select cowrie_event_id from evaluation_chain_steps where cowrie_event_id is not null",
)


def parse_age(value: str) -> timedelta:
    """`90d` or `90` -> 90 days. Days only: retention is not an hourly decision."""
    match = re.fullmatch(r"(\d+)d?", value.strip())
    if not match or int(match.group(1)) < 1:
        raise argparse.ArgumentTypeError(f"expected a number of days such as 90d, got {value!r}")
    return timedelta(days=int(match.group(1)))


def rotated_logs(names: Iterable[str], cutoff: datetime) -> list[str]:
    """Rotated log files whose day ended before the cutoff. Pure.

    The live file has no date suffix and is never returned.
    """
    old = []
    for name in names:
        match = _ROTATED.search(name)
        if (
            match
            and datetime.fromisoformat(match.group(1)).replace(tzinfo=UTC) + timedelta(days=1)
            <= cutoff
        ):
            old.append(name)
    return sorted(old)


def old_recordings(files: dict[str, float], cutoff: datetime, keep: set[str]) -> list[str]:
    """TTY recordings (name -> mtime) older than the cutoff and not kept. Pure."""
    return sorted(
        name
        for name, mtime in files.items()
        if _SHA256.fullmatch(name)
        and name not in keep
        and datetime.fromtimestamp(mtime, UTC) < cutoff
    )


@dataclass(frozen=True)
class IndexState:
    name: str
    is_write_index: bool
    newest: datetime | None  # None: the index holds no events
    referenced: int  # events in it that Postgres points at


def index_verdict(index: IndexState, cutoff: datetime) -> str | None:
    """Why an index is KEPT, or None if it may be dropped. Pure."""
    if index.is_write_index:
        return "the write index"
    if index.newest is not None and index.newest >= cutoff:
        return f"has events newer than the cutoff (newest {index.newest:%Y-%m-%d})"
    if index.referenced:
        return f"{index.referenced} event(s) referenced from Postgres"
    return None


async def _references() -> tuple[set[str], set[str]]:
    sessions: set[str] = set()
    events: set[str] = set()
    async with get_session_factory()() as db:
        for query in _SESSION_REFS:
            sessions.update(r[0] for r in (await db.execute(text(query))).all())
        for query in _EVENT_REFS:
            events.update(r[0] for r in (await db.execute(text(query))).all())
    return sessions, events


def _referenced_query(sessions: set[str], events: set[str]) -> dict:
    should: list[dict] = []
    session_list = sorted(sessions)
    # `terms` takes at most 65,536 values; chunk well below that.
    for i in range(0, len(session_list), 10_000):
        should.append({"terms": {"session.id": session_list[i : i + 10_000]}})
    if events:
        should.append({"ids": {"values": sorted(events)}})
    return {"bool": {"should": should, "minimum_should_match": 1}} if should else {"match_none": {}}


async def _index_states(sessions: set[str], events: set[str]) -> list[IndexState]:
    es = get_es()
    alias = get_settings().es_index
    if not await es.indices.exists_alias(name=alias):
        print(f"  {alias} is a concrete index, not a rollover alias: no backing index to drop")
        return []
    states = []
    for name, body in sorted((await es.indices.get_alias(name=alias)).items()):
        aggs = (
            await es.search(
                index=name,
                size=0,
                aggs={
                    "newest": {"max": {"field": "@timestamp"}},
                    "referenced": {"filter": _referenced_query(sessions, events)},
                },
            )
        )["aggregations"]
        stamp = aggs["newest"].get("value_as_string")
        states.append(
            IndexState(
                name=name,
                is_write_index=bool(body["aliases"][alias].get("is_write_index")),
                newest=datetime.fromisoformat(stamp.replace("Z", "+00:00")) if stamp else None,
                referenced=aggs["referenced"]["doc_count"],
            )
        )
    return states


async def _kept_recordings(sessions: set[str]) -> set[str]:
    if not sessions:
        return set()
    # ponytail: one page of 10,000 close events; page with search_after if a
    # deployment ever has more referenced sessions than that.
    result = await get_es().search(
        index=get_settings().es_index,
        size=10_000,
        query={
            "bool": {
                "filter": [
                    _referenced_query(sessions, set()),
                    {"term": {"event.action": "cowrie.log.closed"}},
                ]
            }
        },
        source=["file.hash.sha256"],
    )
    return {
        hit["_source"]["file"]["hash"]["sha256"]
        for hit in result["hits"]["hits"]
        if hit["_source"].get("file", {}).get("hash", {}).get("sha256")
    }


def _act(apply: bool, path: Path) -> None:
    print(f"  {'deleted' if apply else 'would delete'} {path}")
    if apply:
        path.unlink()


async def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--older-than", type=parse_age, required=True, metavar="DAYS")
    parser.add_argument("--apply", action="store_true", help="delete; without it, a dry run")
    parser.add_argument("--log-dir", action="append", type=Path, metavar="DIR")
    parser.add_argument("--tty-dir", action="append", type=Path, metavar="DIR")
    args = parser.parse_args()
    log_dirs = args.log_dir or sorted(p for p in Path("/prune").glob("*-logs*") if p.is_dir())
    tty_dirs = args.tty_dir or sorted(p for p in Path("/prune").glob("*-tty") if p.is_dir())
    cutoff = datetime.now(UTC) - args.older_than
    print(f"cutoff {cutoff:%Y-%m-%d %H:%M} UTC -- {'APPLYING' if args.apply else 'dry run'}")

    sessions, events = await _references()
    print(f"Postgres references {len(sessions)} sessions and {len(events)} events")

    print("Elasticsearch indices:")
    for index in await _index_states(sessions, events):
        reason = index_verdict(index, cutoff)
        if reason:
            print(f"  keep {index.name}: {reason}")
        else:
            print(f"  {'deleted' if args.apply else 'would delete'} {index.name}")
            if args.apply:
                await get_es().indices.delete(index=index.name)

    print("Rotated raw logs:")
    for directory in log_dirs:
        for name in rotated_logs((p.name for p in directory.iterdir()), cutoff):
            _act(args.apply, directory / name)

    print("TTY recordings:")
    keep = await _kept_recordings(sessions) if tty_dirs else set()
    for directory in tty_dirs:
        files = {p.name: p.stat().st_mtime for p in directory.iterdir() if p.is_file()}
        for name in old_recordings(files, cutoff, keep):
            _act(args.apply, directory / name)
    await get_es().close()


if __name__ == "__main__":
    asyncio.run(_main())
