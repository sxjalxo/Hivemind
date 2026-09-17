import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import (
    EvaluationEvidence,
    EvaluationFinding,
    EvaluationProbeResult,
    EvaluationRun,
)
from app.db.session import get_session_factory


async def _make_run(db) -> uuid.UUID:
    run = EvaluationRun(
        honeypot_id="cowrie-01",
        status="completed",
        started_at=datetime.now(UTC),
        agent_model="llama3.1:8b",
        evaluator_status="unavailable",
        honeypot_fingerprint="sha256:a",
        evaluation_config_fingerprint="sha256:b",
    )
    db.add(run)
    await db.flush()
    return run.id


async def _make_probe(db, run_id: uuid.UUID) -> uuid.UUID:
    probe = EvaluationProbeResult(
        run_id=run_id,
        module="nmap",
        probe_id="http_exposed",
        target="cowrie",
        establishes="service.http",
        fact_status="not_observed",
    )
    db.add(probe)
    await db.flush()
    return probe.id


@pytest.mark.asyncio
async def test_a_finding_with_no_evidence_is_rejected_at_commit() -> None:
    async with get_session_factory()() as db:
        run_id = await _make_run(db)
        db.add(
            EvaluationFinding(
                run_id=run_id,
                characteristic="services",
                severity="medium",
                finding="Expected HTTP service was not exposed",
                source="static",
                finding_key="probe:fixture-1:fixture.fact",
            )
        )
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


@pytest.mark.asyncio
async def test_a_finding_with_one_probe_evidence_commits() -> None:
    async with get_session_factory()() as db:
        run_id = await _make_run(db)
        probe_id = await _make_probe(db, run_id)
        finding = EvaluationFinding(
            run_id=run_id,
            characteristic="services",
            severity="medium",
            finding="Expected HTTP service was not exposed",
            source="static",
            finding_key="probe:fixture-2:fixture.fact",
        )
        db.add(finding)
        await db.flush()
        finding_id = finding.id
        db.add(
            EvaluationEvidence(
                finding_id=finding_id, kind="probe", probe_result_id=probe_id
            )
        )
        await db.commit()

    # Clean up in FK-dependency order: evidence -> finding/probe -> run.
    # (evaluation_findings.run_id and evaluation_probe_results.run_id are
    # plain RESTRICT foreign keys, so the run can't be deleted first.)
    async with get_session_factory()() as db:
        evidence = (
            await db.execute(
                select(EvaluationEvidence).where(
                    EvaluationEvidence.finding_id == finding_id
                )
            )
        ).scalar_one()
        await db.delete(evidence)
        finding = await db.get(EvaluationFinding, finding_id)
        await db.delete(finding)
        probe = await db.get(EvaluationProbeResult, probe_id)
        await db.delete(probe)
        run = await db.get(EvaluationRun, run_id)
        await db.delete(run)
        await db.commit()


@pytest.mark.asyncio
async def test_evidence_kind_must_match_the_populated_reference() -> None:
    async with get_session_factory()() as db:
        run_id = await _make_run(db)
        probe_id = await _make_probe(db, run_id)
        finding = EvaluationFinding(
            run_id=run_id,
            characteristic="services",
            severity="low",
            finding="mismatched kind",
            source="static",
            finding_key="probe:fixture-3:fixture.fact",
        )
        db.add(finding)
        await db.flush()
        # kind says event, but a probe reference is populated.
        db.add(
            EvaluationEvidence(
                finding_id=finding.id, kind="event", probe_result_id=probe_id
            )
        )
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()
