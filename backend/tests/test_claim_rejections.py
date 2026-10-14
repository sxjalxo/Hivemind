"""Why a claim was refused (checklist item 16): every counted rejection has a row."""

import uuid

import pytest
from sqlalchemy import select

from app.db.models import ClaimRejection, ParentType
from app.db.session import get_session_factory
from app.services.analyzer import load_analysis
from app.services.llm.schemas import EvidenceCitation, TechniqueProposal, TechniqueProposals
from app.services.mitre.mapper import map_techniques
from app.services.persistence import (
    REJECTED_TEXT_LIMIT,
    Claim,
    RejectedClaim,
    persist_analysis,
)
from tests.test_evidence_barrier import NOW, TIMESTAMPS, _analysis, _grounded_claim
from tests.test_mitre_mapper import UNRULED, StubClient


def _proposal(technique_id: str, event_id: str) -> TechniqueProposal:
    return TechniqueProposal(
        technique_id=technique_id,
        tactic="Discovery",
        confidence=0.7,
        ai_explanation=f"explains {technique_id}",
        evidence=[EvidenceCitation(event_id=event_id, artifact="x")],
    )


@pytest.mark.asyncio
async def test_the_mapper_says_why_each_proposal_was_refused():
    client = StubClient(
        TechniqueProposals(
            techniques=[
                _proposal("T9999", UNRULED.event_id),  # not in the catalog
                _proposal("T1082", "e-never-offered"),  # cites an event it was not shown
            ]
        )
    )
    result = await map_techniques([UNRULED], client)

    assert result.rejected == len(result.rejections) == 2
    unknown, unoffered = result.rejections
    assert (unknown.reason, unknown.technique_id) == ("unknown_technique", "T9999")
    assert (unoffered.reason, unoffered.cited_event_ids) == (
        "citations_not_offered",
        ["e-never-offered"],
    )
    assert unoffered.stage == "mapping" and unoffered.text == "explains T1082"


async def _rows(analysis_id: uuid.UUID) -> list[ClaimRejection]:
    async with get_session_factory()() as db:
        return (
            (
                await db.execute(
                    select(ClaimRejection).where(ClaimRejection.analysis_id == analysis_id)
                )
            )
            .scalars()
            .all()
        )


async def _delete(analysis_id: uuid.UUID) -> None:
    # Children of the analysis are cleaned by the barrier tests' own helper;
    # here only the rejection rows and the analysis exist besides the one
    # grounded claim, and the foreign key cascades the rejections.
    from tests.test_evidence_barrier import _cleanup

    await _cleanup(analysis_id)


@pytest.mark.asyncio
async def test_every_counted_rejection_is_written_with_its_reason():
    analysis = _analysis("test-claim-rejections")
    ungrounded = Claim(
        kind=ParentType.OBSERVED_BEHAVIOR,
        payload={"label": "y" * (REJECTED_TEXT_LIMIT + 100)},
        evidence=[EvidenceCitation(event_id="e-invented", artifact="x")],
    )
    earlier = RejectedClaim(
        stage="mapping",
        kind="technique_mapping",
        reason="unknown_technique",
        technique_id="T9999",
    )
    await persist_analysis(
        analysis,
        [_grounded_claim(), ungrounded],
        [],
        "test-claim-rejections",
        TIMESTAMPS,
        prior_rejected=1,
        rejections=[earlier],
    )
    try:
        rows = await _rows(analysis.id)
        assert sorted(r.reason for r in rows) == ["citations_unresolved", "unknown_technique"]
        barrier = next(r for r in rows if r.stage == "evidence_barrier")
        assert barrier.kind == "observed_behavior"
        assert barrier.cited_event_ids == ["e-invented"]
        assert len(barrier.text) == REJECTED_TEXT_LIMIT

        loaded = await load_analysis(analysis.id)
        assert loaded.rejected_claims == 2 == len(loaded.rejections)
        # A refused claim is never also a finding.
        assert loaded.observed_behavior == []
    finally:
        await _delete(analysis.id)
    assert await _rows(analysis.id) == []  # the foreign key cascaded


@pytest.mark.asyncio
async def test_an_analysis_from_before_reasons_were_kept_still_reports_its_count():
    analysis = _analysis("test-claim-rejections-legacy")
    await persist_analysis(analysis, [_grounded_claim()], [], "test", TIMESTAMPS, prior_rejected=3)
    try:
        loaded = await load_analysis(analysis.id)
        assert (loaded.rejected_claims, loaded.rejections) == (3, [])
    finally:
        await _delete(analysis.id)


def test_stored_report_snapshots_without_the_new_fields_still_validate():
    from app.models.analysis import SessionAnalysis

    legacy = {
        "id": "a",
        "sessionId": "s",
        "model": "m",
        "analysisType": "session_behavior",
        "status": "completed",
        "createdAt": NOW.isoformat(),
        "durationSeconds": 1,
        "classification": "c",
        "confidence": 0.5,
        "riskScore": 1,
        "risk": "low",
        "behaviorSummary": "b",
        "observedBehavior": [],
        "suspiciousIndicators": [],
        "recommendedActions": [],
        "techniques": [],
    }
    snapshot = SessionAnalysis.model_validate(legacy)
    assert (snapshot.rejected_claims, snapshot.rejections) == (0, [])
