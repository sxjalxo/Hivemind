"""Which persona each sensor ran, and from when (R1). Real Postgres."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete

from app.db.models import PersonaDeployment
from app.db.session import get_session_factory
from app.services import persona_deployments as deployments

SENSORS = ("test-persona-live", "test-persona-eval")
# Well in the past: the tests read "now", and T0 + 3 days must still be before it.
T0 = datetime(2026, 10, 1, 12, tzinfo=UTC)


async def _wipe() -> None:
    async with get_session_factory()() as db:
        await db.execute(
            delete(PersonaDeployment).where(PersonaDeployment.honeypot_id.in_(SENSORS))
        )
        await db.commit()


# Cleanup is inline (try/finally), not an async fixture: a fixture's teardown
# runs as a separate pytest-asyncio task, which this suite has seen trip
# asyncpg's "attached to a different loop" (see tests/test_analyzer.py).


@pytest.mark.asyncio
async def test_a_sensor_with_no_deployment_has_no_persona() -> None:
    await _wipe()
    assert await deployments.active(SENSORS[0]) is None
    assert await deployments.active_digest(SENSORS[0]) is None


@pytest.mark.asyncio
async def test_a_twinned_deploy_records_both_sensors_with_one_digest() -> None:
    await _wipe()
    try:
        await deployments.record(
            SENSORS, "web-server", "sha256:" + "a" * 64, "operator:test", at=T0
        )
        for sensor in SENSORS:
            row = await deployments.active(sensor)
            assert (row.persona, row.digest, row.deployed_by) == (
                "web-server",
                "sha256:" + "a" * 64,
                "operator:test",
            )
            assert row.deployed_at == T0
    finally:
        await _wipe()


@pytest.mark.asyncio
async def test_the_latest_deployment_wins_and_history_is_kept_by_time() -> None:
    await _wipe()
    try:
        await deployments.record(
            SENSORS[:1], "web-server", "sha256:" + "a" * 64, "operator:t", at=T0
        )
        later = T0 + timedelta(days=3)
        await deployments.record(SENSORS[:1], "rpi", "sha256:" + "b" * 64, "operator:t", at=later)
        assert (await deployments.active(SENSORS[0])).persona == "rpi"
        assert await deployments.active_digest(SENSORS[0]) == "sha256:" + "b" * 64
        between = T0 + timedelta(days=1)
        assert (await deployments.active(SENSORS[0], at=between)).persona == "web-server"
        assert await deployments.active(SENSORS[0], at=T0 - timedelta(seconds=1)) is None
    finally:
        await _wipe()


@pytest.mark.asyncio
async def test_a_reverted_sensor_has_no_active_digest_like_before_any_deploy() -> None:
    await _wipe()
    try:
        await deployments.record(SENSORS, "web-server", "sha256:" + "a" * 64, "operator:t", at=T0)
        assert await deployments.active_digest(SENSORS[0]) == "sha256:" + "a" * 64
        later = T0 + timedelta(days=1)
        await deployments.record(
            SENSORS, deployments.PRE_PERSONA, deployments.PRE_PERSONA, "operator:t", at=later
        )
        assert await deployments.active_digest(SENSORS[0]) is None
        assert (await deployments.active(SENSORS[0])).persona == "pre-persona"
    finally:
        await _wipe()
