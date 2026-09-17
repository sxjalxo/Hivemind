import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.db.models import (
    Characteristic,
    EvaluationRun,
    FactStatus,
    ModuleStatus,
    RunStatus,
)
from app.db.session import get_session_factory


@pytest.mark.asyncio
async def test_a_run_round_trips_with_both_fingerprints() -> None:
    run_id = uuid.uuid4()
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                honeypot_id="cowrie-01",
                status=RunStatus.COMPLETED,
                started_at=datetime.now(UTC),
                finished_at=datetime.now(UTC),
                agent_model="llama3.1:8b",
                evaluator_model=None,
                evaluator_status="unavailable",
                honeypot_fingerprint="sha256:aaa",
                evaluation_config_fingerprint="sha256:bbb",
            )
        )
        await db.commit()
    try:
        async with get_session_factory()() as db:
            stored = (
                await db.execute(select(EvaluationRun).where(EvaluationRun.id == run_id))
            ).scalar_one()
            assert stored.honeypot_fingerprint == "sha256:aaa"
            assert stored.evaluation_config_fingerprint == "sha256:bbb"
            # Distinct columns: changing a probe definition must not be
            # attributable to the honeypot.
            assert stored.honeypot_fingerprint != stored.evaluation_config_fingerprint
    finally:
        async with get_session_factory()() as db:
            stored = await db.get(EvaluationRun, run_id)
            await db.delete(stored)
            await db.commit()


def test_fact_status_distinguishes_unknown_from_not_observed() -> None:
    # The whole failure model rests on these being three values, not a bool.
    assert {s.value for s in FactStatus} == {"observed", "not_observed", "unknown"}
    assert ModuleStatus.TIMEOUT.value == "timeout"
    assert Characteristic.ATTACK_POSSIBILITIES.value == "attack_possibilities"


@pytest.mark.asyncio
async def test_two_findings_cannot_share_a_key_within_one_run() -> None:
    """The unique index is what makes "is it fixed?" unambiguous.

    Two rows with one key in a single run give the lifecycle two answers for
    the same question, and which one it reports would depend on row order.
    Enforced in the schema rather than in the producer, because there are
    several producers and there will be more.
    """
    from sqlalchemy.exc import IntegrityError

    from app.db.models import EvaluationEvidence, EvaluationFinding, EvaluationProbeResult

    run_id = uuid.uuid4()
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                honeypot_id="cowrie-key-test",
                status=RunStatus.COMPLETED,
                started_at=datetime.now(UTC),
                finished_at=datetime.now(UTC),
                agent_model="deterministic-probes@1",
                evaluator_model=None,
                evaluator_status="unavailable",
                honeypot_fingerprint="sha256:aaa",
                evaluation_config_fingerprint="sha256:bbb",
            )
        )
        # Flush the run before its children: these tables carry no ORM
        # relationship, so SQLAlchemy cannot infer the insert order from the
        # foreign key and may write the probe first.
        await db.flush()
        probe = EvaluationProbeResult(
            run_id=run_id,
            module="agent",
            probe_id="uname",
            target="cowrie",
            establishes="os.identity",
            value=None,
            fact_status=FactStatus.NOT_OBSERVED,
        )
        db.add(probe)
        await db.flush()

        # Each finding carries evidence, so the evidence trigger cannot be
        # what fires -- the only constraint left is the one under test.
        def _duplicate() -> EvaluationFinding:
            return EvaluationFinding(
                run_id=run_id,
                characteristic=Characteristic.BASIC_COMMANDS.value,
                severity="medium",
                finding="uname did not establish os.identity",
                source="deterministic",
                finding_key="probe:uname:os.identity",
            )

        first = _duplicate()
        db.add(first)
        await db.flush()
        db.add(
            EvaluationEvidence(
                finding_id=first.id, kind="probe", probe_result_id=probe.id
            )
        )

        # The unique index rejects the second at FLUSH, not at commit, so the
        # guard has to cover the write rather than only the commit.
        with pytest.raises(IntegrityError) as caught:
            db.add(_duplicate())
            await db.flush()
            await db.commit()
        await db.rollback()

    assert "ix_findings_run_key" in str(caught.value), (
        f"the write failed, but not on the unique index this test is about: {caught.value}"
    )


@pytest.mark.asyncio
async def test_the_same_key_in_two_different_runs_is_allowed() -> None:
    """The other half of the constraint, and the whole point of the feature.

    A key repeating across runs is not a conflict -- it is the defect
    persisting, which is exactly what the lifecycle needs to see. A unique
    index on `finding_key` alone would have made this impossible while looking
    superficially correct.
    """
    from app.db.models import EvaluationEvidence, EvaluationFinding, EvaluationProbeResult

    run_ids = [uuid.uuid4(), uuid.uuid4()]
    async with get_session_factory()() as db:
        for run_id in run_ids:
            db.add(
                EvaluationRun(
                    id=run_id,
                    honeypot_id="cowrie-key-test",
                    status=RunStatus.COMPLETED,
                    started_at=datetime.now(UTC),
                    finished_at=datetime.now(UTC),
                    agent_model="deterministic-probes@1",
                    evaluator_model=None,
                    evaluator_status="unavailable",
                    honeypot_fingerprint="sha256:aaa",
                    evaluation_config_fingerprint="sha256:bbb",
                )
            )
            await db.flush()
            probe = EvaluationProbeResult(
                run_id=run_id,
                module="agent",
                probe_id="uname",
                target="cowrie",
                establishes="os.identity",
                value=None,
                fact_status=FactStatus.NOT_OBSERVED,
            )
            db.add(probe)
            await db.flush()
            finding = EvaluationFinding(
                run_id=run_id,
                characteristic=Characteristic.BASIC_COMMANDS.value,
                severity="medium",
                finding="uname did not establish os.identity",
                source="deterministic",
                finding_key="probe:uname:os.identity",
            )
            db.add(finding)
            await db.flush()
            db.add(
                EvaluationEvidence(
                    finding_id=finding.id, kind="probe", probe_result_id=probe.id
                )
            )
        await db.commit()

    try:
        async with get_session_factory()() as db:
            stored = (
                (
                    await db.execute(
                        select(EvaluationFinding).where(
                            EvaluationFinding.finding_key == "probe:uname:os.identity"
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert {row.run_id for row in stored} == set(run_ids)
    finally:
        from app.services.evaluation.runs import delete_run

        for run_id in run_ids:
            await delete_run(run_id)
