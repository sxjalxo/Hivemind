import uuid

import pytest
from sqlalchemy import select

from app.db.models import (
    Analysis,
    EvidenceRef,
    IndicatorSession,
    ObservedBehavior,
    RecommendedAction,
    SuspiciousIndicator,
    TechniqueMapping,
)
from app.db.models import Indicator as IndicatorRow
from app.db.session import get_session_factory
from app.seed.seeder import seed
from app.services.analyzer import run_analysis
from app.services.compaction import compact
from app.services.coverage import build_coverage
from app.services.intel import correlate, extract_indicators, list_indicators
from app.services.llm.schemas import EvidenceCitation
from app.services.profiles import build_profile, jaccard
from app.services.session_builder import get_session_events

# Cleanup runs inline, at the end of each test's own coroutine (try/finally) --
# the pattern tests/test_analyzer.py and tests/test_evidence_barrier.py
# already use. This suite additionally writes to the indicators and
# indicator_sessions tables (Task 15's own write path, separate from the
# Task 13 claim barrier), so cleanup here also removes any indicator that
# this test's own session(s) created and left with no remaining link.


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


async def _delete_indicators_for_session(session_id: str) -> None:
    """Undo whatever `correlate` wrote for one session_id.

    Removes this session's indicator_sessions links, then deletes any
    indicator left with zero remaining links -- an indicator another,
    still-live session also cites is left alone.
    """
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
                row = await db.get(IndicatorRow, indicator_id)
                if row:
                    await db.delete(row)
        await db.commit()


def test_jaccard_of_identical_sets_is_one() -> None:
    assert jaccard({"ls", "id"}, {"ls", "id"}) == 1.0


def test_jaccard_of_disjoint_sets_is_zero() -> None:
    assert jaccard({"ls"}, {"whoami"}) == 0.0


def test_jaccard_of_empty_sets_is_zero_not_a_crash() -> None:
    assert jaccard(set(), set()) == 0.0


def test_jaccard_is_symmetric() -> None:
    a, b = {"ls", "id", "ps"}, {"ls", "whoami"}
    assert jaccard(a, b) == jaccard(b, a)


@pytest.mark.asyncio
async def test_extraction_finds_urls_hashes_and_ips() -> None:
    # seed-botnet-01's download event (app/seed/corpus/botnet_dropper.json)
    # carries a real 64-char shasum, url, and outfile -- none of which
    # appear anywhere in command text, so this can only pass if
    # extract_indicators actually reads compacted.downloads, not just
    # regex-scans commands.
    await seed(reset=True)
    events = await get_session_events("seed-botnet-01")
    compacted = compact(events)
    extracted = extract_indicators(compacted)

    types = {payload["type"] for payload, _ in extracted}
    assert "url" in types
    assert "command" in types
    assert "hash" in types
    assert "filename" in types

    for payload, citations in extracted:
        assert citations, f"{payload} was extracted without a citation"

    assert len(compacted.downloads) == 1
    download = compacted.downloads[0]
    assert download.shasum == (
        "9f2b1c4e8a7d6053f1e2b9c8a7d6e5f4b3a2918077665544332211aabbccddee"
    )

    hash_entry = next(
        (p, c) for p, c in extracted if p["type"] == "hash" and p["value"] == download.shasum
    )
    _, hash_citations = hash_entry
    assert any(c.event_id == download.event_id for c in hash_citations), (
        "the hash indicator must be cited to the download event, not a command"
    )

    filename_entry = next(
        (p, c) for p, c in extracted if p["type"] == "filename" and p["value"] == download.outfile
    )
    _, filename_citations = filename_entry
    assert any(c.event_id == download.event_id for c in filename_citations)


@pytest.mark.asyncio
async def test_indicators_accumulate_sessions_across_runs() -> None:
    await seed(reset=True)
    analysis_a = await run_analysis("seed-botnet-01")
    analysis_b = await run_analysis("seed-miner-01")
    try:
        indicators = await list_indicators()
        assert indicators

        for indicator in indicators:
            assert indicator.source in {"OBSERVED", "CORRELATED", "AI INFERENCE", "STATIC ANALYSIS"}
            assert indicator.session_ids
    finally:
        await _delete_analysis_and_children(analysis_a)
        await _delete_analysis_and_children(analysis_b)
        await _delete_indicators_for_session("seed-botnet-01")
        await _delete_indicators_for_session("seed-miner-01")


@pytest.mark.asyncio
async def test_one_analysis_leaves_indicators_observed_with_one_session() -> None:
    # A single call to `correlate` must never claim cross-session
    # correlation: `source` starts (and stays, absent a second session)
    # OBSERVED, with exactly the one session id that was actually offered.
    value = f"203.0.113.{uuid.uuid4().int % 250}"
    extracted = [(
        {"type": "ip", "value": value},
        [EvidenceCitation(event_id="e-1", artifact=f"connection from {value}")],
    )]
    session_a = f"test-corr-a-{uuid.uuid4().hex[:8]}"
    try:
        new_count = await correlate(session_a, extracted)
        assert new_count == 1

        indicators = await list_indicators(type_="ip", q=value)
        assert len(indicators) == 1
        assert indicators[0].source == "OBSERVED"
        assert indicators[0].session_ids == [session_a]
    finally:
        await _delete_indicators_for_session(session_a)


@pytest.mark.asyncio
async def test_reanalyzing_the_same_session_does_not_fabricate_correlation() -> None:
    # This is the regression this test guards: an indicator re-encountered
    # within the SAME session (a re-analysis, or simply appearing again) is
    # NOT a second session. Flipping it to CORRELATED here would assert
    # something that never happened -- the same defect class as a
    # hardcoded risk level, just for a different field.
    value = f"203.0.113.{uuid.uuid4().int % 250}"
    extracted = [(
        {"type": "ip", "value": value},
        [EvidenceCitation(event_id="e-1", artifact=f"connection from {value}")],
    )]
    session_a = f"test-corr-a-{uuid.uuid4().hex[:8]}"
    try:
        await correlate(session_a, extracted)

        new_count_again = await correlate(session_a, extracted)
        assert new_count_again == 0, "the value already existed; nothing new was created"

        indicators = await list_indicators(type_="ip", q=value)
        assert len(indicators) == 1
        reanalyzed = indicators[0]
        assert reanalyzed.source == "OBSERVED", "same session again is not a second session"
        assert reanalyzed.session_ids == [session_a], "must not grow past one session id"
    finally:
        await _delete_indicators_for_session(session_a)


@pytest.mark.asyncio
async def test_indicator_flips_to_correlated_when_seen_in_a_second_session() -> None:
    # Exercises `correlate` directly (the real, production write path) rather
    # than hand-inserting rows: one indicator value offered to two different
    # session_ids must accumulate both sessions and flip its provenance from
    # OBSERVED to CORRELATED -- proving the mechanism, not just the field.
    # A second value, unique to session_b, proves the flip is per-indicator:
    # it must stay OBSERVED even while the shared value next to it flips.
    shared_value = f"203.0.113.{uuid.uuid4().int % 250}"
    unique_value = f"198.51.100.{uuid.uuid4().int % 250}"
    shared = [(
        {"type": "ip", "value": shared_value},
        [EvidenceCitation(event_id="e-1", artifact=f"connection from {shared_value}")],
    )]
    session_a = f"test-corr-a-{uuid.uuid4().hex[:8]}"
    session_b = f"test-corr-b-{uuid.uuid4().hex[:8]}"
    try:
        new_count = await correlate(session_a, shared)
        assert new_count == 1

        indicators = await list_indicators(type_="ip", q=shared_value)
        assert len(indicators) == 1
        assert indicators[0].source == "OBSERVED"
        assert indicators[0].session_ids == [session_a]

        session_b_extracted = shared + [(
            {"type": "ip", "value": unique_value},
            [EvidenceCitation(event_id="e-2", artifact=f"connection from {unique_value}")],
        )]
        new_count_again = await correlate(session_b, session_b_extracted)
        assert new_count_again == 1, "only unique_value is genuinely new this call"

        indicators = await list_indicators(type_="ip", q=shared_value)
        assert len(indicators) == 1
        flipped = indicators[0]
        assert flipped.source == "CORRELATED"
        assert set(flipped.session_ids) == {session_a, session_b}

        indicators = await list_indicators(type_="ip", q=unique_value)
        assert len(indicators) == 1
        still_single = indicators[0]
        assert still_single.source == "OBSERVED", "unique to one session -- must not flip"
        assert still_single.session_ids == [session_b]
    finally:
        await _delete_indicators_for_session(session_a)
        await _delete_indicators_for_session(session_b)


@pytest.mark.asyncio
async def test_attacker_profile_is_built_from_sessions() -> None:
    await seed(reset=True)
    analysis_id = await run_analysis("seed-botnet-01")
    try:
        profile = await build_profile("185.220.101.44")
        assert profile is not None
        assert profile.sessions >= 1
        assert profile.commands
        assert profile.technique_ids
        assert profile.attack_pattern
    finally:
        await _delete_analysis_and_children(analysis_id)
        await _delete_indicators_for_session("seed-botnet-01")


@pytest.mark.asyncio
async def test_profile_of_an_unseen_ip_is_none() -> None:
    assert await build_profile("203.0.113.99") is None


@pytest.mark.asyncio
async def test_coverage_marks_only_rule_backed_techniques_observed() -> None:
    await seed(reset=True)
    analysis_id = await run_analysis("seed-botnet-01")
    try:
        coverage = await build_coverage()

        assert coverage.total_count > 0
        assert coverage.observed_count <= coverage.total_count

        ingress = next(t for t in coverage.techniques if t.id == "T1105")
        assert ingress.observed is True
        assert ingress.evidence
    finally:
        await _delete_analysis_and_children(analysis_id)
        await _delete_indicators_for_session("seed-botnet-01")


@pytest.mark.asyncio
async def test_coverage_scoped_to_a_session_excludes_others() -> None:
    await seed(reset=True)
    analysis_id = await run_analysis("seed-persist-01")
    try:
        coverage = await build_coverage(session_id="seed-persist-01")

        observed = {t.id for t in coverage.techniques if t.observed}
        assert "T1098.004" in observed
    finally:
        await _delete_analysis_and_children(analysis_id)
        await _delete_indicators_for_session("seed-persist-01")


@pytest.mark.asyncio
async def test_coverage_marks_llm_inferred_technique_as_not_observed() -> None:
    # seed-unmapped-01's commands (dmidecode, /sys/class/dmi, ip route,
    # systemctl) are deliberately chosen to match none of the rulebook's
    # patterns -- see app/services/mitre/rules.py and rulebook.yaml. Any
    # technique mapping for this session can only have come from the LLM
    # gap-fill, so this proves the observed=False boundary against a real
    # analysis run rather than a hand-built TechniqueMapping row.
    await seed(reset=True)
    analysis_id = await run_analysis("seed-unmapped-01")
    try:
        async with get_session_factory()() as db:
            mappings = (
                (
                    await db.execute(
                        select(TechniqueMapping).where(
                            TechniqueMapping.analysis_id == analysis_id
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert mappings, "no rule in the pinned catalog matches seed-unmapped-01's commands"
        assert all(m.source == "llm" for m in mappings)

        coverage = await build_coverage(session_id="seed-unmapped-01")
        matched = [t for t in coverage.techniques if t.session_count > 0]
        assert matched

        for technique in matched:
            assert technique.observed is False
            assert technique.ai_explanation
            assert technique.evidence
    finally:
        await _delete_analysis_and_children(analysis_id)
        await _delete_indicators_for_session("seed-unmapped-01")
