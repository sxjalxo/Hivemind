"""The persona experiment's schedule (R3). Pure: no ES, no database."""

from datetime import UTC, datetime
from itertools import pairwise
from types import SimpleNamespace

import pytest

from app.services.experiment.schedule import (
    PERSONAS_DIR,
    SCHEDULE_PATH,
    STOCK,
    Schedule,
    ScheduleError,
    Slot,
    due,
    in_place,
    load_schedule,
    persona_of,
)
from app.services.persona_deployments import PRE_PERSONA

T0 = datetime(2026, 10, 1, tzinfo=UTC)
TWO = Schedule("test-sensor-r", T0, 3, ("web-server", STOCK))


def _write(tmp_path, text: str):
    path = tmp_path / "experiment.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _row(persona: str, at: datetime):
    return SimpleNamespace(persona=persona, deployed_at=at)


def test_slots_follow_each_other_from_the_start() -> None:
    assert TWO.slots == [
        Slot(0, "web-server", T0, datetime(2026, 10, 4, tzinfo=UTC)),
        Slot(1, STOCK, datetime(2026, 10, 4, tzinfo=UTC), datetime(2026, 10, 7, tzinfo=UTC)),
    ]
    assert TWO.end == datetime(2026, 10, 7, tzinfo=UTC)


def test_the_due_slot_is_half_open() -> None:
    assert due(TWO, datetime(2026, 9, 30, 23, 59, tzinfo=UTC)) is None
    assert due(TWO, T0).index == 0
    assert due(TWO, datetime(2026, 10, 4, tzinfo=UTC)).index == 1  # a boundary is the next slot
    assert due(TWO, TWO.end) is None


def test_stock_is_recorded_as_the_pre_persona_setup() -> None:
    assert persona_of(STOCK) == PRE_PERSONA
    assert persona_of("rpi") == "rpi"


@pytest.mark.parametrize("start", ['"2026-10-01T00:00:00Z"', "2026-10-01T00:00:00Z"])
def test_a_schedule_loads_with_a_quoted_or_bare_utc_start(tmp_path, start: str) -> None:
    path = _write(
        tmp_path,
        f"sensor: test-sensor-r\nstart: {start}\nblock_days: 3\nblocks: [web-server, stock]\n",
    )
    schedule = load_schedule(path)
    assert schedule == TWO
    assert schedule.start.utcoffset().total_seconds() == 0


@pytest.mark.parametrize(
    ("body", "says"),
    [
        ("start: null\nblock_days: 3\nblocks: [rpi]", "no start"),
        ('start: "2026-10-01T00:00:00"\nblock_days: 3\nblocks: [rpi]', "timezone"),
        ('start: "yesterday"\nblock_days: 3\nblocks: [rpi]', "ISO 8601"),
        ('start: "2026-10-01T00:00:00Z"\nblock_days: 0\nblocks: [rpi]', "block_days"),
        ('start: "2026-10-01T00:00:00Z"\nblock_days: "3"\nblocks: [rpi]', "block_days"),
        ('start: "2026-10-01T00:00:00Z"\nblock_days: 3\nblocks: []', "no blocks"),
        ('start: "2026-10-01T00:00:00Z"\nblock_days: 3\nblocks: [rpi, mainframe]', "mainframe"),
    ],
)
def test_an_unusable_schedule_is_refused(tmp_path, body: str, says: str) -> None:
    with pytest.raises(ScheduleError, match=says):
        load_schedule(_write(tmp_path, "sensor: test-sensor-r\n" + body + "\n"))


def test_the_committed_schedule_is_not_started_yet() -> None:
    with pytest.raises(ScheduleError, match="no start"):
        load_schedule(SCHEDULE_PATH)


def test_the_committed_schedule_rotates_four_arms_three_times(tmp_path) -> None:
    text = SCHEDULE_PATH.read_text(encoding="utf-8").replace(
        "start: null", 'start: "2026-10-01T00:00:00Z"'
    )
    schedule = load_schedule(_write(tmp_path, text), PERSONAS_DIR)
    arms = schedule.arms
    assert (schedule.sensor, schedule.block_days, len(arms)) == ("gcp-wild-01", 3, 12)
    assert sorted(set(arms)) == ["db-server", "rpi", STOCK, "web-server"]
    assert all(arms.count(a) == 3 for a in set(arms))
    assert all(a != b for a, b in pairwise(arms))  # never the same arm twice in a row
    cycles = [arms[0:4], arms[4:8], arms[8:12]]
    for arm in set(arms):  # a different position in every cycle
        assert len({cycle.index(arm) for cycle in cycles}) == 3


def test_a_slot_is_in_place_only_after_a_deployment_inside_it() -> None:
    slot = TWO.slots[0]
    now = datetime(2026, 10, 2, tzinfo=UTC)
    carried = [_row("web-server", datetime(2026, 9, 30, tzinfo=UTC))]
    assert not in_place(slot, carried, now)  # same persona, but from before the slot
    fresh = [*carried, _row("web-server", datetime(2026, 10, 1, 6, tzinfo=UTC))]
    assert in_place(slot, fresh, now)
    replaced = [*fresh, _row("rpi", datetime(2026, 10, 1, 9, tzinfo=UTC))]
    assert not in_place(slot, replaced, now)  # something else was deployed since
    future = [*fresh, _row("rpi", datetime(2026, 10, 3, tzinfo=UTC))]
    assert in_place(slot, future, now)  # rows after `at` are not in force yet
    stock = TWO.slots[1]
    later = datetime(2026, 10, 5, tzinfo=UTC)
    assert in_place(stock, [_row(PRE_PERSONA, datetime(2026, 10, 4, 1, tzinfo=UTC))], later)
    assert not in_place(stock, [], later)
