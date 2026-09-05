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
