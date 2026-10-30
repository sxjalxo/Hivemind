from datetime import UTC, datetime, timedelta
from itertools import pairwise
from types import SimpleNamespace

from app.services.periods import Period, periods
from app.services.persona_deployments import PRE_PERSONA

T0 = datetime(2026, 10, 20, tzinfo=UTC)


def at(hours: float) -> datetime:
    return T0 + timedelta(hours=hours)


def deploy(persona: str, hours: float):
    return SimpleNamespace(persona=persona, deployed_at=at(hours))


def change(kind: str, hours: float):
    return SimpleNamespace(kind=kind, at=at(hours))


def test_no_deployments_is_one_period_with_no_persona():
    assert periods([], [], at(0), at(48)) == [Period(at(0), at(48), None, ())]


def test_deployment_inside_window_splits_pre_persona_then_persona():
    out = periods([deploy("web-server", 10)], [], at(0), at(48))

    assert [(p.start, p.end, p.persona) for p in out] == [
        (at(0), at(10), PRE_PERSONA),
        (at(10), at(48), "web-server"),
    ]
    assert out[0].opened_by == ()
    assert out[1].opened_by == ("persona:web-server",)


def test_deployment_before_window_is_one_period_with_that_persona():
    assert periods([deploy("web-server", -5)], [], at(0), at(48)) == [
        Period(at(0), at(48), "web-server", ())
    ]


def test_deployment_exactly_at_window_start_is_in_force_not_a_cut():
    assert periods([deploy("web-server", 0)], [], at(0), at(48)) == [
        Period(at(0), at(48), "web-server", ())
    ]


def test_change_inside_persona_period_splits_it_and_keeps_the_persona():
    out = periods([deploy("web-server", -5)], [change("rate-limit", 20)], at(0), at(48))

    assert [(p.start, p.end, p.persona) for p in out] == [
        (at(0), at(20), "web-server"),
        (at(20), at(48), "web-server"),
    ]
    assert out[1].opened_by == ("rate-limit",)


def test_revert_to_pre_persona_labels_the_following_period():
    out = periods([deploy("web-server", 10), deploy(PRE_PERSONA, 30)], [], at(0), at(48))

    assert [p.persona for p in out] == [PRE_PERSONA, "web-server", PRE_PERSONA]
    assert out[2].opened_by == ("persona:pre-persona",)


def test_periods_are_contiguous_and_cover_the_window():
    deployments = [deploy("web-server", 10), deploy(PRE_PERSONA, 30)]
    changes = [change("rate-limit", 15), change("note", 40)]

    out = periods(deployments, changes, at(0), at(48))

    assert out[0].start == at(0)
    assert out[-1].end == at(48)
    assert all(p.start < p.end for p in out)
    assert all(a.end == b.start for a, b in pairwise(out))


def test_end_not_after_start_gives_no_periods():
    assert periods([deploy("web-server", 10)], [change("note", 5)], at(48), at(48)) == []
    assert periods([], [], at(48), at(0)) == []


def test_deployment_and_change_at_same_instant_make_one_boundary():
    out = periods([deploy("web-server", 10)], [change("rate-limit", 10)], at(0), at(48))

    assert [(p.start, p.end) for p in out] == [(at(0), at(10)), (at(10), at(48))]
    assert out[1].persona == "web-server"
    assert out[1].opened_by == ("persona:web-server", "rate-limit")


def test_unsorted_deployments_before_window_take_the_latest_persona():
    deployments = [deploy("c", -1), deploy("a", -10), deploy("b", -5)]

    assert periods(deployments, [], at(0), at(48)) == [Period(at(0), at(48), "c", ())]


def test_changes_and_deployments_outside_the_window_cut_nothing():
    out = periods(
        [deploy("web-server", 60)],
        [change("rate-limit", -3), change("note", 48), change("note", 60)],
        at(0),
        at(48),
    )

    assert out == [Period(at(0), at(48), PRE_PERSONA, ())]


def test_deployment_exactly_at_window_end_cuts_nothing():
    assert periods([deploy("web-server", 48)], [], at(0), at(48)) == [
        Period(at(0), at(48), PRE_PERSONA, ())
    ]
