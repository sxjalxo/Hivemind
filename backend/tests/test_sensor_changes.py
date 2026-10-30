"""Non-persona sensor changes: the service and the operator CLI. Real Postgres."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete

from app.db.models import SensorChange
from app.db.session import get_engine, get_session_factory
from app.services import sensor_changes
from scripts import record_change

SENSOR = "test-sensor-a"
# Well in the past: the tests read "now", and T0 + a day must still be before it.
T0 = datetime(2026, 10, 1, 12, tzinfo=UTC)


async def _wipe() -> None:
    async with get_session_factory()() as db:
        await db.execute(delete(SensorChange).where(SensorChange.honeypot_id.like("test-sensor-%")))
        await db.commit()


# Cleanup is inline (try/finally), not an async fixture: see tests/test_persona_deployments.py.


@pytest.mark.asyncio
async def test_history_is_oldest_first_whatever_the_recording_order() -> None:
    await _wipe()
    try:
        later = T0 + timedelta(days=1)
        await sensor_changes.record(SENSOR, "rate-limit", "10 per minute", "operator:t", at=later)
        await sensor_changes.record(SENSOR, "note", "first", "operator:t", at=T0)
        await sensor_changes.record("test-sensor-b", "note", "other sensor", "operator:t", at=T0)
        rows = await sensor_changes.history(SENSOR)
        assert [(r.kind, r.detail, r.at) for r in rows] == [
            ("note", "first", T0),
            ("rate-limit", "10 per minute", later),
        ]
        assert rows[0].recorded_by == "operator:t"
        assert await sensor_changes.history("test-sensor-none") == []
    finally:
        await _wipe()


@pytest.mark.asyncio
async def test_an_unknown_kind_is_refused_and_nothing_is_written() -> None:
    await _wipe()
    try:
        with pytest.raises(ValueError):
            await sensor_changes.record(SENSOR, "reboot", "x", "operator:t", at=T0)
        assert await sensor_changes.history(SENSOR) == []
    finally:
        await _wipe()


@pytest.mark.asyncio
async def test_the_cli_records_one_row_as_the_operator() -> None:
    await _wipe()
    try:
        # main() runs its own event loop; drop the pooled connections bound to this one.
        await get_engine().dispose()
        code = await asyncio.to_thread(
            record_change.main, [SENSOR, "--kind", "note", "--at", "2026-10-01T00:00:00Z", "hello"]
        )
        assert code == 0
        rows = await sensor_changes.history(SENSOR)
        assert len(rows) == 1
        assert (rows[0].kind, rows[0].detail) == ("note", "hello")
        assert rows[0].at == datetime(2026, 10, 1, tzinfo=UTC)
        assert rows[0].recorded_by.startswith("operator:")
    finally:
        await _wipe()


@pytest.mark.parametrize("bad", ["yesterday", "2026-10-01T00:00:00"])
def test_the_cli_refuses_a_bad_or_zoneless_time(bad: str) -> None:
    with pytest.raises(SystemExit) as stop:
        record_change.main([SENSOR, "--at", bad, "hello"])
    assert stop.value.code != 0
