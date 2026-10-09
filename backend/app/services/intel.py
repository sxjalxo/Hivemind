import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, literal_column, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db.models import Indicator as IndicatorRow
from app.db.models import IndicatorSession
from app.db.session import get_session_factory
from app.models.intel import Indicator
from app.services.compaction import CompactedSession
from app.services.llm.schemas import EvidenceCitation

_URL = re.compile(r"https?://[^\s'\"|;)]+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_indicators(
    compacted: CompactedSession,
) -> list[tuple[dict, list[EvidenceCitation]]]:
    """Pull IOCs out of a session with deterministic regex and direct field reads.

    No LLM: extraction must be reproducible. Each IOC carries the citation of
    the command (or download event) it came from, so the Task 13 barrier can
    ground it.

    A downloaded file's `hash`/`url`/`filename` are read directly from
    `compacted.downloads` (`app.services.compaction.CompactedDownload`) --
    fields Cowrie's `cowrie.session.file_download` event reports directly,
    not something that needs regex-scanning out of command text. A malware
    hash never appears in a command line at all (the `wget ...` that
    triggers the download never mentions its own target's shasum), so
    without this, the single most actionable IOC a honeypot produces --
    a hash a defender can pivot on -- could never become an indicator.
    """
    found: dict[tuple[str, str], list[EvidenceCitation]] = {}

    def record(type_: str, value: str, citation: EvidenceCitation) -> None:
        found.setdefault((type_, value), []).append(citation)

    for command in compacted.commands:
        citation = EvidenceCitation(
            event_id=command.event_id, artifact=command.command
        )
        record("command", command.command, citation)
        for url in _URL.findall(command.command):
            record("url", url, citation)
        for ip in _IPV4.findall(command.command):
            record("ip", ip, citation)
        for digest in _SHA256.findall(command.command):
            record("hash", digest, citation)

    for download in compacted.downloads:
        label = download.outfile or download.url or "downloaded file"
        citation = EvidenceCitation(
            event_id=download.event_id, artifact=f"download: {label}"
        )
        if download.shasum:
            record("hash", download.shasum, citation)
        if download.url:
            record("url", download.url, citation)
        if download.outfile:
            record("filename", download.outfile, citation)

    attacker_citation = EvidenceCitation(
        event_id=compacted.first_event_id, artifact=f"connection from {compacted.attacker_ip}"
    )
    record("ip", compacted.attacker_ip, attacker_citation)
    if compacted.username:
        record("username", compacted.username, attacker_citation)

    return [
        ({"type": type_, "value": value}, citations)
        for (type_, value), citations in found.items()
    ]


async def correlate(
    session_id: str, extracted: list[tuple[dict, list[EvidenceCitation]]]
) -> int:
    """Upsert indicators and link them to this session.

    `source` is derived from how many DISTINCT sessions actually link to the
    indicator afterward -- never from whether the row already existed. An
    indicator's value can be re-encountered many times within the very same
    session (a re-analysis, or simply appearing on more than one command);
    none of that is a second session, and marking it CORRELATED on that
    basis would fabricate the one thing CORRELATED is supposed to assert:
    that this value was genuinely observed across more than one session.
    So the flip is computed AFTER the (session_id, indicator) link is
    upserted, by counting the distinct session ids actually linked to that
    indicator: >1 is CORRELATED, exactly 1 is OBSERVED (including the
    "existing indicator, same session, re-analyzed" case, which still
    counts to exactly one distinct session and must stay OBSERVED).

    Returns the number of indicator VALUES this call created for the first
    time ever (never seen in any prior session) -- not the number of
    session links created, and unaffected by re-linking an already-seen
    session.

    **Both writes are upserts, and that is a correctness property, not a
    tidiness one.** This was a SELECT, then an INSERT if the SELECT found
    nothing. Two analyses running at once both read "not there" and both
    insert, and the second violates `uq_indicator_type_value`: an
    IntegrityError that rolls the whole transaction back and surfaces as a
    500 on an analysis that had already done all its work. That is not an
    exotic race -- every session records its attacker's IP as an indicator,
    so any two analyses of sessions from the same attacker collide on it,
    and nothing anywhere serialises them.

    The upsert also fixes a quieter bug of the same origin, and this is the
    half worth reading twice. `source` is CORRELATED only when the value was
    genuinely seen in more than one session, and it is computed by counting
    distinct linked sessions AFTER the link is written. Under the old code
    two concurrent analyses each inserted their own link, each counted one
    (neither could see the other's uncommitted row), and both wrote
    OBSERVED -- so a value that really did appear in two sessions was
    reported as appearing in one, permanently, with nothing to notice it.
    `ON CONFLICT DO UPDATE` takes a row lock on the conflicting indicator
    for the rest of the transaction, so the second analysis now blocks until
    the first commits and then counts both links. The serialisation falls
    out of the statement that was needed anyway; no extra locking.

    `xmax = 0` is how the first write reports whether it inserted or
    updated. Postgres sets `xmax` to the locking transaction on the DO
    UPDATE path and leaves it zero on a fresh insert, so this distinguishes
    the two without a second query -- which matters because the answer has
    to come from the same statement that did the write, or it is a second
    race in place of the one just closed.
    """
    now = datetime.now(timezone.utc)
    new_count = 0

    async with get_session_factory()() as db:
        for payload, _ in extracted:
            upsert = (
                pg_insert(IndicatorRow)
                .values(
                    type=payload["type"],
                    value=payload["value"],
                    confidence=1.0,
                    first_seen=now,
                    last_seen=now,
                    source="OBSERVED",
                    tags=[],
                )
                .on_conflict_do_update(
                    constraint="uq_indicator_type_value",
                    # `first_seen` is deliberately NOT touched: it means the
                    # first time this value was ever seen, and an upsert that
                    # refreshed it would erase exactly the history the field
                    # exists to record.
                    set_={"last_seen": now},
                )
                .returning(IndicatorRow.id, literal_column("xmax") == 0)
            )
            indicator_id, inserted = (await db.execute(upsert)).one()
            if inserted:
                new_count += 1

            await db.execute(
                pg_insert(IndicatorSession)
                .values(indicator_id=indicator_id, session_id=session_id)
                # Re-analysing a session links the same pair again. DO
                # NOTHING rather than DO UPDATE: there is no non-key column
                # to refresh, and the row already says everything it says.
                .on_conflict_do_nothing(
                    index_elements=[
                        IndicatorSession.indicator_id,
                        IndicatorSession.session_id,
                    ]
                )
            )

            session_count = (
                await db.execute(
                    select(func.count(func.distinct(IndicatorSession.session_id))).where(
                        IndicatorSession.indicator_id == indicator_id
                    )
                )
            ).scalar_one()
            await db.execute(
                update(IndicatorRow)
                .where(IndicatorRow.id == indicator_id)
                .values(source="CORRELATED" if session_count > 1 else "OBSERVED")
            )

        await db.commit()

    return new_count


def _like_escaped(term: str) -> str:
    """Escape a user term for a LIKE pattern.

    `%` and `_` are wildcards, so an unescaped `%` matches everything and
    turns a filter into a no-op that still looks like it filtered. That is
    the quietest kind of wrong this codebase keeps finding: same shape of
    answer, silently wider. The backslash must be escaped first, or it would
    go on to escape the escapes added after it.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def list_indicators(
    type_: str | None = None, q: str | None = None, limit: int | None = None
) -> list[Indicator]:
    """Every indicator, filtered, with the sessions each was seen in.

    Two queries total, not one per indicator. This loaded every row and then
    issued a SELECT per row for its session links -- fine against a seed
    corpus, and a query per IOC once a honeypot has been collecting for a
    while. `create_report` calls it with no filter and keeps one session's
    worth, so a report cost a full scan plus N round trips.

    `q` is filtered in SQL rather than in Python for the same reason, and
    `type_` always was. Both narrow the row set BEFORE the link query, so the
    second query carries only the ids actually being returned.

    Ordering is explicit. Postgres guarantees none without it -- physical
    order shifts under vacuum -- and this list is rendered in a UI, so rows
    silently reshuffling between two identical requests reads as data
    changing. `session_ids` is sorted for the same reason.
    """
    async with get_session_factory()() as db:
        statement = select(IndicatorRow)
        if type_:
            statement = statement.where(IndicatorRow.type == type_)
        if q:
            statement = statement.where(
                IndicatorRow.value.ilike(f"%{_like_escaped(q)}%", escape="\\")
            )
        statement = statement.order_by(IndicatorRow.last_seen.desc(), IndicatorRow.id)
        # Applied after the ordering, so a bounded page is the NEWEST rows
        # rather than whichever the planner happened to reach first. None for
        # internal callers: `create_report` reads every indicator and keeps one
        # session's worth, so a cap here would drop evidence from a report.
        if limit is not None:
            statement = statement.limit(limit)
        rows = (await db.execute(statement)).scalars().all()
        if not rows:
            return []

        links = (
            await db.execute(
                select(IndicatorSession).where(
                    IndicatorSession.indicator_id.in_([row.id for row in rows])
                )
            )
        ).scalars().all()

        by_indicator: dict[uuid.UUID, list[str]] = {}
        for link in links:
            by_indicator.setdefault(link.indicator_id, []).append(link.session_id)

        return [
            Indicator(
                id=str(row.id),
                type=row.type,
                value=row.value,
                confidence=row.confidence,
                first_seen=row.first_seen.isoformat().replace("+00:00", "Z"),
                last_seen=row.last_seen.isoformat().replace("+00:00", "Z"),
                session_ids=sorted(by_indicator.get(row.id, [])),
                source=row.source,
                tags=row.tags or [],
            )
            for row in rows
        ]
