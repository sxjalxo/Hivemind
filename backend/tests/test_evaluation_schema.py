import uuid
from datetime import UTC, datetime, timezone

import pytest
from sqlalchemy import delete, select
from sqlalchemy import text as sa_text

from app.db.models import (
    Characteristic,
    EvaluationCategoryScore,
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


async def test_category_score_records_why_a_rating_is_missing() -> None:
    """A null rating must carry its own reason, per characteristic.

    The run-level `evaluator_status` is an aggregate across all six
    characteristics and cannot answer "why is THIS one blank".
    """
    run_id = uuid.uuid4()
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                honeypot_id="cowrie-01",
                status="completed",
                started_at=datetime.now(timezone.utc),
                agent_model="none",
                evaluator_status="completed",
                honeypot_fingerprint="sha256:test",
                evaluation_config_fingerprint="sha256:test",
                started_by="unauthenticated",
            )
        )
        # Flush the run before its child: these tables carry no ORM
        # relationship, so SQLAlchemy cannot infer the insert order from the
        # foreign key and may write the category score first (see the same
        # note on EvaluationProbeResult above).
        await db.flush()
        db.add(
            EvaluationCategoryScore(
                run_id=run_id,
                characteristic="os_identity",
                deterministic_score=0.5,
                evaluator_rating=None,
                evaluator_status="unavailable",
                evaluator_detail="no evidence gathered for this characteristic",
            )
        )
        await db.commit()

    async with get_session_factory()() as db:
        row = (
            await db.execute(
                select(EvaluationCategoryScore).where(
                    EvaluationCategoryScore.run_id == run_id
                )
            )
        ).scalar_one()
        assert row.evaluator_status == "unavailable"
        assert row.evaluator_detail == "no evidence gathered for this characteristic"

    async with get_session_factory()() as db:
        await db.execute(
            delete(EvaluationCategoryScore).where(EvaluationCategoryScore.run_id == run_id)
        )
        await db.execute(delete(EvaluationRun).where(EvaluationRun.id == run_id))
        await db.commit()


async def test_evaluator_status_has_no_server_default() -> None:
    """A forgotten column must fail loudly, not file itself as `unrecorded`.

    `unrecorded` means "this row predates the column". A server default would
    let a NEW row that forgot the column claim the same thing, which is a gap
    in the record disguised as a recorded fact.
    """
    async with get_session_factory()() as db:
        default = (
            await db.execute(
                sa_text(
                    "SELECT column_default FROM information_schema.columns "
                    "WHERE table_name = 'evaluation_category_scores' "
                    "AND column_name = 'evaluator_status'"
                )
            )
        ).scalar_one()
        assert default is None
