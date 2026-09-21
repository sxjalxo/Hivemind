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


# --- what the target IS, not just where it is ----------------------------


def test_a_target_defaults_to_cowrie_and_needs_a_container() -> None:
    """`cowrie` is the kind whose machinery needs something to exec into."""
    from pydantic import ValidationError

    assert HoneypotTarget(host="h", container_name="c").kind == "cowrie"

    with pytest.raises(ValidationError, match="container_name"):
        HoneypotTarget(host="h")


def test_a_generic_target_needs_no_container() -> None:
    """A real VM or bare host is not a container and must not have to pretend."""
    target = HoneypotTarget(
        kind="generic", host="192.0.2.10", ssh_port=22, ssh_password="hunter2"
    )

    assert target.container_name is None
    assert target.ssh_port == 22


def test_only_a_cowrie_target_simulates_commands() -> None:
    """The property B3 rests on.

    Cowrie's shell backend emulates every command, which is the only reason
    the attack chains are safe to run at all. A real host runs them.
    """
    assert HoneypotTarget(host="h", container_name="c").simulates_commands is True
    generic = HoneypotTarget(kind="generic", host="h", ssh_password="hunter2")
    assert generic.simulates_commands is False
    assert HoneypotTarget(host="h", container_name="c").has_own_event_log is True
    assert generic.has_own_event_log is False


def test_an_unknown_kind_is_refused_rather_than_treated_as_generic() -> None:
    """A typo must not silently pick a behaviour.

    Refusing is safe in both directions here: `kind` decides whether we run
    destructive commands AND whether we skip machinery that cannot work, so
    a value nobody defined has no correct interpretation.
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HoneypotTarget(kind="real-vm", host="h")


def test_a_generic_target_must_state_its_own_password() -> None:
    """The default is a Cowrie fact, not a universal one.

    Cowrie accepts any password and the credential is not a secret. Against
    a real machine the same default authenticates with a string nobody chose
    -- and fails in the shape of a honeypot refusing a login rather than a
    setting nobody filled in.
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="ssh_password"):
        HoneypotTarget(kind="generic", host="192.0.2.10", ssh_port=22)

    with pytest.raises(ValidationError, match="ssh_password"):
        HoneypotTarget(kind="generic", host="192.0.2.10", ssh_port=22, ssh_password="")

    stated = HoneypotTarget(
        kind="generic", host="192.0.2.10", ssh_port=22, ssh_password="hunter2"
    )
    assert stated.ssh_password == "hunter2"


def test_a_cowrie_target_keeps_the_shared_default() -> None:
    """Requiring one here would put a credential in the map for no gain."""
    target = HoneypotTarget(host="cowrie", container_name="hivemind-cowrie-1")

    assert target.ssh_password == "hivemind-evaluation"
