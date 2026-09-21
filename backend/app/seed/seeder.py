import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from elasticsearch.helpers import async_bulk

from app.config import get_settings
from app.es.bootstrap import PIPELINE_ID, bootstrap_es
from app.es.client import get_es

CORPUS_DIR = Path(__file__).parent / "corpus"

# How long before "now" the corpus's LAST event sits.
#
# The anchor used to be a fixed calendar date, `datetime(2026, 8, 20, 10, 0)`.
# That works until the date falls out of the dashboard's widest window (30d,
# see `app.services.dashboard._WINDOWS`), at which point every screen the
# corpus exists to fill goes empty -- silently, because an out-of-range
# document is still indexed, still counted by `seeded_count()` and still
# fetchable by id. Nothing reports it; the panels are just blank.
#
# It expired on 2026-09-20 and the suite only noticed because one dashboard
# test asserts a SPECIFIC seeded IP. The other three had been passing on live
# honeypot traffic that happened to satisfy them -- the agent's own probes run
# `uname -a`, which is exactly what `test_top_commands_counts_seeded_commands`
# looks for. A corpus test that live traffic can satisfy is not testing the
# corpus, which is why the margin below is small enough to keep the whole
# corpus inside even the narrowest window (1h) rather than merely inside 30d.
SEED_TRAILING_MARGIN = timedelta(minutes=5)


def seed_base_time(span_seconds: int, now: datetime | None = None) -> datetime:
    """The instant offset 0 maps to, so the corpus ends `now - margin`.

    Anchored backwards from the END of the corpus rather than forwards from
    its start: forwards, a corpus that grew past the margin would put events
    in the FUTURE, and a honeypot event dated after the present moment is a
    nonsense this system should never render -- it would also sit outside
    every window, reproducing the bug in the opposite direction.
    """
    anchor = now or datetime.now(timezone.utc)
    return anchor - SEED_TRAILING_MARGIN - timedelta(seconds=span_seconds)


HONEYPOT = {"id": "cowrie-01", "name": "Cowrie SSH (med-ws-04)"}


def load_corpus(now: datetime | None = None) -> list[dict]:
    """Expand corpus fixtures into Cowrie-format events with stable ids.

    Deterministic in everything that identifies an event: the same files in
    produce the same `_id`s, the same ordering and the same INTERVALS out.
    Only the absolute anchor moves, so that a corpus seeded today lands in
    the windows the UI queries (see `seed_base_time`). `_id` is derived from
    the session and index, never the timestamp, which is what keeps
    `seed(reset=True)` and `_seeded_query()` exact across a re-anchor.

    `now` is injectable so a caller can pin the anchor; nothing in the
    application passes it.
    """
    fixtures = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(CORPUS_DIR.glob("*.json"))
    ]
    # Read from the fixtures rather than hardcoded: an added session with a
    # later offset has to move the anchor with it, or it lands in the future.
    span = max(
        (raw["offset"] for fixture in fixtures for raw in fixture["events"]), default=0
    )
    base = seed_base_time(span, now)

    events: list[dict] = []
    for fixture in fixtures:
        session = fixture["session"]
        for index, raw in enumerate(fixture["events"]):
            event = {k: v for k, v in raw.items() if k != "offset"}
            timestamp = base + timedelta(seconds=raw["offset"])
            event.update(
                {
                    "_id": f"{session}-{index:03d}",
                    "session": session,
                    "src_ip": fixture["src_ip"],
                    "src_port": fixture["src_port"],
                    "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                }
            )
            events.append(event)
    return events


def _seeded_query() -> dict:
    """Match only real corpus documents, not merely anything labelled seeded.

    Belt and braces: labels.seeded says a document claims to be seed data;
    matching against load_corpus()'s actual _id set says it is really ours.
    A document that sets labels.seeded: true without being one of our ids
    (e.g. a mislabeled fixture in an unrelated test, or future corruption)
    must not be counted, nor deleted by seed(reset=True).

    Elasticsearch's `_id` field is of type `_id`, which rejects prefix/
    wildcard queries outright ("Can only use prefix queries on keyword,
    text and wildcard fields - not on [_id]"), so a prefix check on "seed-"
    is not expressible directly. The `ids` query is the field's supported
    lookup and is exact rather than prefix-based, which is even tighter.
    """
    ids = [event["_id"] for event in load_corpus()]
    return {
        "bool": {
            "filter": [
                {"term": {"labels.seeded": True}},
                {"ids": {"values": ids}},
            ]
        }
    }


def _to_bulk_action(event: dict, index: str) -> dict:
    doc = {k: v for k, v in event.items() if k != "_id"}
    doc["honeypot"] = dict(HONEYPOT)
    doc["labels"] = {"seeded": True}
    return {
        "_op_type": "index",
        "_index": index,
        "_id": event["_id"],
        "pipeline": PIPELINE_ID,
        "_source": doc,
    }


async def seeded_count() -> int:
    settings = get_settings()
    await get_es().indices.refresh(index=settings.es_index)
    result = await get_es().count(index=settings.es_index, query=_seeded_query())
    return int(result["count"])


async def seed(reset: bool = False) -> int:
    """Index the corpus, replacing any previous copy of it.

    The delete is UNCONDITIONAL now; `reset` no longer selects it. Fixed ids
    used to make this idempotent by overwrite, and that stops being true the
    moment `es_index` is a rollover alias: document ids are unique per INDEX,
    not per alias, so re-seeding after a rollover writes a second copy of
    every event into the new write index while the original sits in the old
    one. `seeded_count` then reports 102 of 51 documents, every seeded session
    renders twice, and nothing about it looks like a bug -- there is no error,
    just doubled data.

    Deleting first cannot produce that, whatever the index topology, because
    `delete_by_query` resolves an alias across all of its indices while an
    indexing request only ever reaches the write index. The cost is one extra
    query against 51 documents.

    `reset` is kept in the signature: callers pass it to say "I mean to
    replace the corpus", and `scripts/seed.py --reset` still reads correctly.
    It simply no longer changes what happens, because the safe behaviour is
    now the only behaviour.

    Not atomic: between the delete and the bulk, `seeded_count()` briefly
    answers 0. Only a concurrent caller could observe that, and the one
    automatic caller is `main.lifespan`, which runs once before the first
    request is served.
    """
    settings = get_settings()
    await bootstrap_es()

    await get_es().delete_by_query(
        index=settings.es_index,
        query=_seeded_query(),
        refresh=True,
        conflicts="proceed",
    )

    events = load_corpus()
    actions = [_to_bulk_action(e, settings.es_index) for e in events]
    await async_bulk(get_es(), actions, refresh="wait_for")
    return len(actions)


async def _main() -> None:
    parser = argparse.ArgumentParser(description="Seed the honeypot event corpus")
    parser.add_argument("--reset", action="store_true", help="delete seeded docs first")
    args = parser.parse_args()
    count = await seed(reset=args.reset)
    print(f"indexed {count} seeded events")
    await get_es().close()


if __name__ == "__main__":
    asyncio.run(_main())
