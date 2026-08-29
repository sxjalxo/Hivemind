import re
from datetime import datetime, timezone

from sqlalchemy import func, select

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
    """Pull IOCs out of a session with deterministic regex.

    No LLM: extraction must be reproducible. Each IOC carries the citation of
    the command it came from, so the Task 13 barrier can ground it.
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
    """
    now = datetime.now(timezone.utc)
    new_count = 0

    async with get_session_factory()() as db:
        for payload, _ in extracted:
            existing = (
                (
                    await db.execute(
                        select(IndicatorRow).where(
                            IndicatorRow.type == payload["type"],
                            IndicatorRow.value == payload["value"],
                        )
                    )
                )
                .scalars()
                .first()
            )

            if existing is None:
                existing = IndicatorRow(
                    type=payload["type"],
                    value=payload["value"],
                    confidence=1.0,
                    first_seen=now,
                    last_seen=now,
                    source="OBSERVED",
                    tags=[],
                )
                db.add(existing)
                await db.flush()
                new_count += 1
            else:
                existing.last_seen = now
                db.add(existing)

            link = await db.get(IndicatorSession, (existing.id, session_id))
            if link is None:
                db.add(
                    IndicatorSession(indicator_id=existing.id, session_id=session_id)
                )
                await db.flush()

            session_count = (
                await db.execute(
                    select(func.count(func.distinct(IndicatorSession.session_id))).where(
                        IndicatorSession.indicator_id == existing.id
                    )
                )
            ).scalar_one()
            existing.source = "CORRELATED" if session_count > 1 else "OBSERVED"
            db.add(existing)

        await db.commit()

    return new_count


async def list_indicators(
    type_: str | None = None, q: str | None = None
) -> list[Indicator]:
    async with get_session_factory()() as db:
        statement = select(IndicatorRow)
        if type_:
            statement = statement.where(IndicatorRow.type == type_)
        rows = (await db.execute(statement)).scalars().all()

        results: list[Indicator] = []
        for row in rows:
            if q and q.lower() not in row.value.lower():
                continue
            links = (
                (
                    await db.execute(
                        select(IndicatorSession).where(
                            IndicatorSession.indicator_id == row.id
                        )
                    )
                )
                .scalars()
                .all()
            )
            results.append(
                Indicator(
                    id=str(row.id),
                    type=row.type,
                    value=row.value,
                    confidence=row.confidence,
                    first_seen=row.first_seen.isoformat().replace("+00:00", "Z"),
                    last_seen=row.last_seen.isoformat().replace("+00:00", "Z"),
                    session_ids=[link.session_id for link in links],
                    source=row.source,
                    tags=row.tags or [],
                )
            )
        return results
