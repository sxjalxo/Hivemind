"""The persona experiment's report (R3), end to end on synthetic test-sensor data."""

from datetime import UTC, datetime, timedelta

import pytest

from app.services import persona_deployments
from app.services.experiment.read import Block
from app.services.experiment.report import (
    BlockRow,
    Report,
    _secondary,
    _tests,
    build,
    exclusion,
    render,
)
from app.services.experiment.schedule import STOCK, Schedule
from app.services.experiment.sessions import PRIMARY, Tally
from app.services.persona_deployments import PRE_PERSONA
from scripts import persona_experiment
from tests.test_experiment_read import _events, _wipe
from tests.test_experiment_sessions import _session

X = "test-sensor-x"
T0 = datetime(2026, 10, 1, tzinfo=UTC)
ARMS = {"web-server", STOCK}


def _block(hours: float, arm: str | None = "web-server", opened: bool = True) -> Block:
    return Block(T0, T0 + timedelta(hours=hours), arm, opened)


@pytest.mark.parametrize(
    ("block", "covered", "total", "tally", "reason"),
    [
        (
            _block(30, opened=False),
            30,
            30,
            Tally([_session("a")]),
            "did not start with a deployment",
        ),
        (_block(30, arm="rpi"), 30, 30, Tally([_session("a")]), "rpi is not an arm"),
        (_block(30, arm=None), 30, 30, Tally([_session("a")]), "no persona is not an arm"),
        (_block(23), 23, 23, Tally([_session("a")]), "shorter than 24 h"),
        (_block(30), 14, 30, Tally([_session("a")]), "coverage below one half (14 of 30 hours)"),
        (_block(30), 30, 30, Tally([], cut=3), "no logged-in session"),
        (_block(30), 15, 30, Tally([_session("a")]), None),
    ],
)
def test_why_a_block_is_left_out(block, covered, total, tally, reason) -> None:
    got = exclusion(block, ARMS, covered, total, tally)
    assert (got is None) if reason is None else (reason in got)


def _session_rows(start: datetime, sid: str, *, commands=(), download=False, seconds=30):
    s = timedelta(seconds=1)
    rows = [
        (start, sid, "cowrie.session.connect", {}, X),
        (start + s, sid, "cowrie.login.success", {}, X),
    ]
    for i, command in enumerate(commands):
        rows.append(
            (
                start + (2 + i) * s,
                sid,
                "cowrie.command.input",
                {"process": {"command_line": command}},
                X,
            )
        )
    if download:
        rows.append(
            (
                start + 9 * s,
                sid,
                "cowrie.session.file_download.failed",
                {"file": {"url": "http://h/x86_64"}},
                X,
            )
        )
    rows.append((start + seconds * s, sid, "cowrie.session.closed", {}, X))
    return rows


@pytest.mark.asyncio
async def test_the_report_end_to_end() -> None:
    schedule = Schedule(X, T0, 1, ("web-server", STOCK))
    day2 = T0 + timedelta(days=1)
    await _wipe()
    try:
        await persona_deployments.record([X], "web-server", "d", "operator:t", at=T0)
        await persona_deployments.record([X], PRE_PERSONA, "d", "operator:t", at=day2)
        rows = []
        for hour in range(24):  # one event every hour in both blocks: full coverage
            rows += [(T0 + timedelta(hours=hour), f"w{hour}", "cowrie.session.connect", {}, X)]
            rows += [(day2 + timedelta(hours=hour), f"s{hour}", "cowrie.session.connect", {}, X)]
        rows += _session_rows(
            T0 + timedelta(hours=1), "web-a", commands=["uname -a"], download=True
        )
        rows += _session_rows(T0 + timedelta(hours=2), "web-b", commands=["uname -a"])
        rows += _session_rows(
            day2 - timedelta(seconds=10), "web-cut", seconds=30
        )  # cut by the switch
        rows += _session_rows(day2 + timedelta(hours=3), "stock-a")
        await _events(rows)

        report = await build(schedule, T0 + timedelta(days=2))
        web, stock = report.rows
        assert (web.block.arm, web.excluded, web.tally.cut) == ("web-server", None, 1)
        assert [s.session_id for s in web.tally.sessions] == ["web-a", "web-b"]
        assert web.tally.not_logged_in == 24
        assert web.session_view["download_share"] == pytest.approx(0.5)
        assert (stock.block.arm, stock.excluded, len(stock.tally.sessions)) == (STOCK, None, 1)
        assert report.tests is None  # one block per arm: nothing to test
        assert report.secondary["web-server"]["techniques"] == {"T1082": 1.0}

        text = render(report)
        assert not text.startswith("INTERIM")
        assert "not enough blocks" in text
        assert "included" in text and "web-server" in text

        interim = render(await build(schedule, T0 + timedelta(days=1, hours=12)))
        assert interim.startswith("INTERIM -- the schedule is not finished")
    finally:
        await _wipe()


def test_the_script_refuses_an_unusable_schedule(tmp_path, capsys) -> None:
    path = tmp_path / "experiment.yaml"
    path.write_text(
        "sensor: test-sensor-x\nstart: null\nblock_days: 3\nblocks: [rpi]\n", encoding="utf-8"
    )
    assert persona_experiment.main(["--schedule", str(path)]) == 1
    assert "no start" in capsys.readouterr().err


def test_the_script_says_when_the_experiment_has_not_started(tmp_path, capsys) -> None:
    path = tmp_path / "experiment.yaml"
    path.write_text(
        'sensor: test-sensor-x\nstart: "2026-10-01T00:00:00Z"\nblock_days: 3\nblocks: [rpi]\n',
        encoding="utf-8",
    )
    code = persona_experiment.main(["--schedule", str(path), "--now", "2026-09-30T00:00:00Z"])
    assert code == 0
    assert "not started" in capsys.readouterr().out


def _row(i: int, arm: str) -> BlockRow:
    start = T0 + timedelta(days=i)
    view = {m: float(i * 7 % 5 + k) / 10 for k, m in enumerate((*PRIMARY, "duration_median_s"))}
    tally = Tally([_session(f"s{i}", commands=["uname -a"])])
    return BlockRow(
        Block(start, start + timedelta(days=1), arm, True), 24, 24, tally, None, view, dict(view)
    )


def test_the_permutation_section_is_rendered_for_two_arms_of_two_blocks() -> None:
    rows = [_row(i, arm) for i, arm in enumerate([STOCK, "web-server", STOCK, "web-server"])]
    tests = _tests(rows)
    assert set(tests) == {"session_view", "script_view"}
    for view in tests.values():
        assert set(view) == set(PRIMARY)
        assert all(
            0 < p <= 1 and 0 < adj <= 1 and exhaustive for p, adj, exhaustive in view.values()
        )

    schedule = Schedule(X, T0, 1, (STOCK, "web-server", STOCK, "web-server"))
    report = Report(
        schedule, schedule.end, (T0, schedule.end), 0, rows, [], tests, _secondary(rows)
    )
    text = render(report)
    assert "p=" in text and "holm=" in text and "(exhaustive)" in text
    assert "smallest attainable p with these block counts: 0.3333" in text  # 2 equal arms: 2 / 6
    assert "web-server - stock:" in text
