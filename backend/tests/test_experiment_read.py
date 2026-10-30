"""What the persona experiment reads from Postgres and ES (R3). Synthetic test-sensor data only."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete

from app.config import get_settings
from app.db.models import PersonaDeployment, SensorChange
from app.db.session import get_session_factory
from app.es.client import get_es
from app.services import persona_deployments
from app.services.experiment import read
from app.services.experiment.read import Block, blocks_as_run, coverage, read_sessions, window
from app.services.experiment.schedule import STOCK, Schedule
from app.services.persona_deployments import PRE_PERSONA

X = "test-sensor-x"
T0 = datetime(2026, 10, 1, tzinfo=UTC)
SCHEDULE = Schedule(X, T0, 1, ("web-server", STOCK))


async def _wipe() -> None:
    await get_es().delete_by_query(
        index=get_settings().es_index,
        query={"prefix": {"honeypot.id": "test-sensor-"}},
        refresh=True,
        conflicts="proceed",
    )
    async with get_session_factory()() as db:
        for model in (PersonaDeployment, SensorChange):
            await db.execute(delete(model).where(model.honeypot_id.like("test-sensor-%")))
        await db.commit()


async def _events(rows) -> None:
    """rows: (at, session, action, extra fields dict, honeypot id)."""
    operations = []
    for at, session, action, extra, honeypot in rows:
        operations += [
            {"index": {"_index": get_settings().es_index}},
            {
                "@timestamp": at.isoformat(),
                "honeypot": {"id": honeypot, "name": "experiment"},
                "session": {"id": session},
                "event": {"action": action},
                **extra,
            },
        ]
    await get_es().bulk(operations=operations, refresh=True)


def test_the_window_stops_at_now_or_the_schedule_end() -> None:
    assert window(SCHEDULE, T0 + timedelta(hours=5)) == (T0, T0 + timedelta(hours=5))
    assert window(SCHEDULE, T0 + timedelta(days=9)) == (T0, SCHEDULE.end)


@pytest.mark.asyncio
async def test_blocks_are_cut_at_the_recorded_deployments() -> None:
    await _wipe()
    try:
        late = T0 + timedelta(hours=2)
        await persona_deployments.record([X], "web-server", "d", "operator:t", at=late)
        await persona_deployments.record(
            [X], PRE_PERSONA, "d", "operator:t", at=T0 + timedelta(days=1)
        )
        blocks = await blocks_as_run(SCHEDULE, T0 + timedelta(days=3))
        assert blocks == [
            Block(T0, late, STOCK, False),  # the sliver before the first switch
            Block(late, T0 + timedelta(days=1), "web-server", True),
            Block(T0 + timedelta(days=1), T0 + timedelta(days=2), STOCK, True),
        ]
        assert blocks[1].hours == pytest.approx(22.0)
    finally:
        await _wipe()


@pytest.mark.asyncio
async def test_a_deployment_at_the_start_opens_the_first_block() -> None:
    await _wipe()
    try:
        await persona_deployments.record([X], "web-server", "d", "operator:t", at=T0)
        (block,) = await blocks_as_run(SCHEDULE, T0 + timedelta(days=1, hours=1))
        assert (block.arm, block.opened_by_deployment) == ("web-server", True)
    finally:
        await _wipe()


@pytest.mark.asyncio
async def test_coverage_counts_hours_with_any_event() -> None:
    await _wipe()
    try:
        start = T0 + timedelta(hours=10, minutes=30)
        await _events(
            [
                (T0 + timedelta(hours=10, minutes=45), "c1", "cowrie.session.connect", {}, X),
                (T0 + timedelta(hours=12, minutes=5), "c2", "cowrie.client.version", {}, X),
                (
                    T0 + timedelta(hours=11, minutes=5),
                    "c3",
                    "cowrie.session.connect",
                    {},
                    "test-sensor-other",
                ),
            ]
        )
        # 10:30 -> 12:30 overlaps the hours 10, 11 and 12; 11 has only another sensor's event.
        assert await coverage(X, start, start + timedelta(hours=2)) == (2, 3)
    finally:
        await _wipe()


@pytest.mark.asyncio
async def test_sessions_are_read_whole_and_in_order_across_pages(monkeypatch) -> None:
    monkeypatch.setattr(read, "_PAGE", 2)
    await _wipe()
    try:
        at = T0 + timedelta(hours=1)
        s = timedelta(seconds=1)
        await _events(
            [
                (
                    at + 3 * s,
                    "a",
                    "cowrie.command.input",
                    {"process": {"command_line": "uname -a"}},
                    X,
                ),
                (at, "a", "cowrie.session.connect", {}, X),
                (at + s, "a", "cowrie.login.success", {}, X),
                (at + 2 * s, "a", "cowrie.client.version", {}, X),  # not an action we read
                (
                    at + 4 * s,
                    "a",
                    "cowrie.session.file_download.failed",
                    {"file": {"url": "http://h/arm7"}},
                    X,
                ),
                (at + 5 * s, "a", "cowrie.session.closed", {}, X),
                (at, "b", "cowrie.session.connect", {}, X),
                (at + s, "b", "cowrie.session.closed", {}, X),
                (at, "c", "cowrie.session.connect", {}, "test-sensor-other"),
                (
                    T0 - timedelta(hours=1),
                    "d",
                    "cowrie.session.connect",
                    {},
                    X,
                ),  # before the window
            ]
        )
        sessions, read_count = await read_sessions(X, T0, T0 + timedelta(days=1))
        assert read_count == 7
        by_id = {x.session_id: x for x in sessions}
        assert sorted(by_id) == ["a", "b"]
        a = by_id["a"]
        assert (a.first, a.last, a.logged_in) == (at, at + 5 * s, True)
        assert (a.commands, a.download_archs) == (("uname -a",), ("arm",))
        assert by_id["b"].logged_in is False
    finally:
        await _wipe()
