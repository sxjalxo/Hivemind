"""Rotation from the experiment schedule (R3). No database, no VM: both are replaced."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.services.experiment.schedule import STOCK, Schedule, ScheduleError
from app.services.persona_deployments import PRE_PERSONA
from scripts import deploy_persona
from scripts import rotate_personas as rotate

T0 = datetime(2026, 10, 1, tzinfo=UTC)
SCHEDULE = Schedule("test-sensor-r", T0, 3, ("web-server", STOCK))
IN_SLOT_0 = datetime(2026, 10, 2, tzinfo=UTC)
IN_SLOT_1 = datetime(2026, 10, 5, tzinfo=UTC)


@pytest.fixture
def world(monkeypatch):
    """Schedule, deployment rows and a recorder in place of the real deploy."""
    state = SimpleNamespace(rows=[], calls=[], code=0)

    async def history(sensor: str):
        assert sensor == "test-sensor-r"
        return state.rows

    def deploy(argv):
        state.calls.append(argv)
        return state.code

    monkeypatch.setattr(rotate, "load_schedule", lambda: SCHEDULE)
    monkeypatch.setattr(deploy_persona, "SENSORS", ("test-sensor-r", "test-sensor-r2"))
    monkeypatch.setattr(rotate, "_history", history)
    monkeypatch.setattr(deploy_persona, "main", deploy)
    return state


def _row(persona: str, at: datetime):
    return SimpleNamespace(persona=persona, deployed_at=at)


def test_before_the_start_nothing_is_due(world, capsys) -> None:
    assert rotate.main(["--apply"], now=datetime(2026, 9, 30, tzinfo=UTC)) == 0
    assert "not started" in capsys.readouterr().out
    assert world.calls == []


def test_after_the_last_block_the_last_arm_stays(world, capsys) -> None:
    assert rotate.main(["--apply"], now=SCHEDULE.end) == 0
    assert "experiment over" in capsys.readouterr().out
    assert world.calls == []


def test_the_dry_run_says_what_it_would_run_and_runs_nothing(world, capsys) -> None:
    assert rotate.main([], now=IN_SLOT_0) == 0
    out = capsys.readouterr().out
    assert "would run: python -m scripts.deploy_persona web-server --apply" in out
    assert world.calls == []


def test_apply_deploys_the_due_persona_and_returns_its_exit_code(world) -> None:
    world.code = 3
    assert rotate.main(["--apply"], now=IN_SLOT_0) == 3
    assert world.calls == [["web-server", "--apply"]]


def test_a_carried_over_persona_is_deployed_again(world) -> None:
    world.rows = [_row("web-server", datetime(2026, 9, 30, tzinfo=UTC))]
    assert rotate.main(["--apply"], now=IN_SLOT_0) == 0
    assert world.calls == [["web-server", "--apply"]]


def test_stock_is_a_revert(world) -> None:
    world.rows = [_row("web-server", datetime(2026, 10, 1, 1, tzinfo=UTC))]
    assert rotate.main(["--apply"], now=IN_SLOT_1) == 0
    assert world.calls == [["--revert", "--apply"]]


def test_a_block_in_place_is_left_alone(world, capsys) -> None:
    world.rows = [_row(PRE_PERSONA, datetime(2026, 10, 4, 2, tzinfo=UTC))]
    assert rotate.main(["--apply"], now=IN_SLOT_1) == 0
    out = capsys.readouterr().out
    assert "in place" in out and "2026-10-07 00:00Z" in out  # the next switch
    assert world.calls == []


def test_an_unusable_schedule_deploys_nothing(world, monkeypatch, capsys) -> None:
    def refuse():
        raise ScheduleError("the schedule has no start yet")

    monkeypatch.setattr(rotate, "load_schedule", refuse)
    assert rotate.main(["--apply"], now=IN_SLOT_0) == 1
    assert "no start" in capsys.readouterr().err
    assert world.calls == []


def test_an_unreachable_database_deploys_nothing(world, monkeypatch, capsys) -> None:
    async def down(sensor: str):
        raise ConnectionRefusedError

    monkeypatch.setattr(rotate, "_history", down)
    assert rotate.main(["--apply"], now=IN_SLOT_0) == 1
    assert "ConnectionRefusedError" in capsys.readouterr().err
    assert world.calls == []


def test_a_schedule_for_another_sensor_deploys_nothing(world, monkeypatch, capsys) -> None:
    monkeypatch.setattr(deploy_persona, "SENSORS", ("gcp-wild-01", "gcp-eval-01"))
    assert rotate.main(["--apply"], now=IN_SLOT_0) == 1
    err = capsys.readouterr().err
    assert "test-sensor-r" in err and "nothing was changed" in err
    assert world.calls == []
