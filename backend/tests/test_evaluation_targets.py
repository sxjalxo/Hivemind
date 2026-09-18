"""Per-honeypot evaluation targets.

Containment is the property under test as much as routing is: the map is
server-side settings, so there is still no path from an HTTP request to an
arbitrary host.
"""

import pytest

from app.config import HoneypotTarget, Settings
from app.services.evaluation import targets


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_no_map_configured_uses_the_single_target_for_any_honeypot() -> None:
    """Today's behaviour, unchanged. One honeypot needs no map."""
    resolved = targets.resolve("cowrie-01", _settings())

    assert resolved.host == "cowrie"
    assert resolved.container_name == "hivemind-cowrie-1"


def test_a_mapped_honeypot_uses_its_own_target() -> None:
    resolved = targets.resolve(
        "cowrie-degraded",
        _settings(
            evaluation_targets={
                "cowrie-degraded": HoneypotTarget(
                    host="127.0.0.1", ssh_port=2322, container_name="hivemind-degraded-1"
                )
            }
        ),
    )

    assert (resolved.host, resolved.ssh_port) == ("127.0.0.1", 2322)
    assert resolved.container_name == "hivemind-degraded-1"


def test_an_unmapped_honeypot_is_refused_once_a_map_exists() -> None:
    """The failure that would otherwise be silent and wrong.

    Falling back to the default target here would evaluate honeypot A while
    labelling the run honeypot B -- every score, finding and fingerprint filed
    against the wrong decoy. Refusing is the only safe answer, and it is the
    same class of mis-attribution the target fingerprint exists to prevent.
    """
    configured = _settings(
        evaluation_targets={
            "cowrie-degraded": HoneypotTarget(
                host="127.0.0.1", container_name="hivemind-degraded-1"
            )
        }
    )

    with pytest.raises(targets.UnknownTargetError) as caught:
        targets.resolve("cowrie-01", configured)

    assert "cowrie-01" in str(caught.value)


def test_the_password_is_never_required_in_a_map_entry() -> None:
    """Credentials for a decoy are not per-honeypot secrets worth demanding.

    Cowrie accepts any password; requiring one per entry would put a
    credential in settings for no gain and make the map tedious enough that
    nobody writes it.
    """
    resolved = targets.resolve(
        "x",
        _settings(
            evaluation_targets={"x": HoneypotTarget(host="h", container_name="c")}
        ),
    )

    assert resolved.ssh_username == "root"
    assert resolved.ssh_password


@pytest.mark.asyncio
async def test_a_configured_target_admits_a_honeypot_with_no_events_yet(monkeypatch) -> None:
    """A freshly built comparison honeypot has captured nothing.

    The registry is derived from indexed events, so without this a brand-new
    degraded Cowrie -- exactly the thing a discrimination experiment needs --
    is refused until somebody attacks it first.
    """
    from app.config import get_settings
    from app.routers import evaluation as router

    get_settings.cache_clear()
    monkeypatch.setenv(
        "EVALUATION_TARGETS",
        '{"cowrie-fresh": {"host": "127.0.0.1", "container_name": "hivemind-fresh-1"}}',
    )
    try:
        assert "cowrie-fresh" in set(get_settings().evaluation_targets)
        assert router.targets.resolve("cowrie-fresh", get_settings()).host == "127.0.0.1"
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_the_unreachable_message_names_the_setting_the_address_came_from() -> None:
    """Block C made the old advice wrong, not merely incomplete.

    It told the reader to set EVALUATION_TARGET_HOST while quoting a host that
    came from EVALUATION_TARGETS -- pointing them at a setting the run was not
    reading. An error message that sends someone to edit the wrong file is
    worse than one that says less.
    """
    from app.services.evaluation import runs
    from app.services.evaluation.agent import EvaluationTarget

    dead = EvaluationTarget(host="127.0.0.1", port=59999, username="root", password="x")

    with pytest.raises(runs.TargetUnreachableError) as mapped:
        await runs._assert_target_reachable(
            dead, timeout_seconds=1.0, hint="This address came from EVALUATION_TARGETS['x']."
        )
    assert "EVALUATION_TARGETS['x']" in str(mapped.value)
    assert "set EVALUATION_TARGET_HOST" not in str(mapped.value)

    with pytest.raises(runs.TargetUnreachableError) as unmapped:
        await runs._assert_target_reachable(dead, timeout_seconds=1.0)
    assert "EVALUATION_TARGET_HOST" in str(unmapped.value)
