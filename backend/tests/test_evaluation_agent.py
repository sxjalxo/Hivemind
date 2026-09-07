import asyncio
import time

import paramiko
import pytest

from app.services.evaluation import agent
from app.services.evaluation.probes import Probe


def _fake_open_session():
    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    def _factory(target):
        return _Session()

    return _factory


@pytest.mark.asyncio
async def test_exceeding_the_command_budget_leaves_remaining_facts_unknown(monkeypatch) -> None:
    probes = (
        Probe(id="p1", characteristic="basic_commands", command="uname -a", establishes="os.identity"),
        Probe(id="p2", characteristic="basic_commands", command="whoami", establishes="user.identity"),
        Probe(id="p3", characteristic="file_system", command="ls /", establishes="fs.root"),
    )
    monkeypatch.setattr(agent, "load_probes", lambda: probes)

    async def _fake_exec(session, command: str) -> tuple[str, int]:
        return f"output of {command}", 0

    monkeypatch.setattr(agent, "_execute", _fake_exec)
    monkeypatch.setattr(agent, "_open_session", _fake_open_session())

    outcome = await agent.run_probes(
        agent.EvaluationTarget(host="cowrie", port=2222, username="root", password="x"),
        agent.AgentBudget(max_commands=2, max_seconds=60),
    )

    by_id = {o.probe_id: o for o in outcome.observations}
    assert outcome.module_status == "budget_exceeded"
    assert by_id["p1"].fact_status == "observed"
    assert by_id["p2"].fact_status == "observed"
    # The third probe never ran. It is unknown, NOT not_observed -- we did
    # not look, so we cannot say the fact is absent.
    assert by_id["p3"].fact_status == "unknown"


@pytest.mark.asyncio
async def test_every_probe_runs_within_budget(monkeypatch) -> None:
    probes = (
        Probe(id="p1", characteristic="basic_commands", command="uname -a", establishes="os.identity"),
    )
    monkeypatch.setattr(agent, "load_probes", lambda: probes)

    async def _fake_exec(session, command: str) -> tuple[str, int]:
        return "Linux med-ws-04", 0

    monkeypatch.setattr(agent, "_execute", _fake_exec)
    monkeypatch.setattr(agent, "_open_session", _fake_open_session())

    outcome = await agent.run_probes(
        agent.EvaluationTarget(host="cowrie", port=2222, username="root", password="x"),
        agent.AgentBudget(max_commands=10, max_seconds=60),
    )

    assert outcome.module_status == "completed"
    assert outcome.observations[0].value == "Linux med-ws-04"


@pytest.mark.asyncio
async def test_a_connection_failure_leaves_every_probe_unknown_not_error_only(monkeypatch) -> None:
    probes = (
        Probe(id="p1", characteristic="basic_commands", command="uname -a", establishes="os.identity"),
    )
    monkeypatch.setattr(agent, "load_probes", lambda: probes)

    def _boom(target):
        raise OSError("connection refused")

    monkeypatch.setattr(agent, "_open_session", _boom)

    outcome = await agent.run_probes(
        agent.EvaluationTarget(host="cowrie", port=2222, username="root", password="x"),
        agent.AgentBudget(max_commands=10, max_seconds=60),
    )

    assert outcome.module_status == "error"
    assert outcome.observations[0].fact_status == "unknown"


@pytest.mark.asyncio
async def test_an_authentication_failure_returns_an_error_outcome_instead_of_raising(monkeypatch) -> None:
    """paramiko.AuthenticationException is not an OSError subclass -- prior to
    the fix it escaped run_probes entirely instead of producing a
    ModuleOutcome, crashing the whole evaluation on a rejected credential."""
    probes = (
        Probe(id="p1", characteristic="basic_commands", command="uname -a", establishes="os.identity"),
    )
    monkeypatch.setattr(agent, "load_probes", lambda: probes)

    def _boom(target):
        raise paramiko.AuthenticationException("auth failed")

    monkeypatch.setattr(agent, "_open_session", _boom)

    outcome = await agent.run_probes(
        agent.EvaluationTarget(host="cowrie", port=2222, username="root", password="x"),
        agent.AgentBudget(max_commands=10, max_seconds=60),
    )

    assert outcome.module_status == "error"
    assert outcome.observations[0].fact_status == "unknown"


@pytest.mark.asyncio
async def test_a_nonzero_exit_with_empty_output_is_unknown_not_absent(monkeypatch) -> None:
    """A command that fails and prints nothing has told us nothing -- it must
    not be conflated with a command that ran cleanly and found nothing."""
    probes = (
        Probe(id="p1", characteristic="file_system", command="touch /tmp/.probe", establishes="fs.writable"),
    )
    monkeypatch.setattr(agent, "load_probes", lambda: probes)

    async def _fake_exec(session, command: str) -> tuple[str, int]:
        return "", 1

    monkeypatch.setattr(agent, "_execute", _fake_exec)
    monkeypatch.setattr(agent, "_open_session", _fake_open_session())

    outcome = await agent.run_probes(
        agent.EvaluationTarget(host="cowrie", port=2222, username="root", password="x"),
        agent.AgentBudget(max_commands=10, max_seconds=60),
    )

    assert outcome.module_status == "completed"
    assert outcome.observations[0].fact_status == "unknown"


@pytest.mark.asyncio
async def test_a_zero_exit_with_empty_output_is_not_observed(monkeypatch) -> None:
    """A command that ran cleanly and produced nothing is a genuine finding
    of absence, distinct from a failed command that told us nothing."""
    probes = (
        Probe(id="p1", characteristic="file_system", command="ls /root/secrets", establishes="fs.secrets"),
    )
    monkeypatch.setattr(agent, "load_probes", lambda: probes)

    async def _fake_exec(session, command: str) -> tuple[str, int]:
        return "", 0

    monkeypatch.setattr(agent, "_execute", _fake_exec)
    monkeypatch.setattr(agent, "_open_session", _fake_open_session())

    outcome = await agent.run_probes(
        agent.EvaluationTarget(host="cowrie", port=2222, username="root", password="x"),
        agent.AgentBudget(max_commands=10, max_seconds=60),
    )

    assert outcome.module_status == "completed"
    assert outcome.observations[0].fact_status == "not_observed"


class _HangingChannel:
    """Simulates a paramiko Channel whose exit-status exchange never
    completes -- e.g. Cowrie closing the session without ever reporting an
    exit status. exit_status_ready() always says no. recv_exit_status()
    really blocks (a bounded 5s stand-in for paramiko's genuinely unbounded
    wait), so pre-fix code -- which called it unconditionally -- actually
    stalls instead of merely raising, and the test's outer timeout below
    catches that as a real failure rather than a silent pass."""

    def exit_status_ready(self) -> bool:
        return False

    def recv_exit_status(self) -> int:
        time.sleep(5)
        return 0


class _HangingStdout:
    channel = _HangingChannel()

    def read(self) -> bytes:
        return b"partial output before the hang"


class _HangingClient:
    def exec_command(self, command: str, timeout: int):
        return None, _HangingStdout(), None


class _HangingSession:
    client = _HangingClient()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.mark.asyncio
async def test_a_probe_whose_exit_status_never_arrives_is_unknown_not_a_hang(monkeypatch) -> None:
    """paramiko's recv_exit_status() blocks on an internal event with no
    timeout of its own -- it can hang forever if the remote never completes
    the exit-status exchange, as Cowrie can. _execute must poll a bounded
    deadline instead of ever calling the blocking method, and run_probes
    must record that probe unknown and continue to the next one rather than
    stall the whole run. Unlike the other tests here, this one exercises the
    real _execute (only _open_session is faked), since the bug lives inside
    _execute's body, not in anything a test would normally replace."""
    probes = (
        Probe(id="p1", characteristic="basic_commands", command="uname -a", establishes="os.identity"),
        Probe(id="p2", characteristic="basic_commands", command="whoami", establishes="user.identity"),
    )
    monkeypatch.setattr(agent, "load_probes", lambda: probes)
    monkeypatch.setattr(agent, "_open_session", lambda target: _HangingSession())
    # Shrink the deadline and poll interval so the test is fast and
    # deterministic -- this compares against the fake's simulated 5s hang,
    # not against a real-clock tick of a few milliseconds.
    # raising=False: these constants don't exist pre-fix. Setting them
    # anyway (rather than asserting they exist) means this test's failure
    # mode against unfixed code is the actual hang it's meant to catch, not
    # an unrelated AttributeError from monkeypatch itself.
    monkeypatch.setattr(agent, "PER_COMMAND_TIMEOUT_SECONDS", 0.05, raising=False)
    monkeypatch.setattr(agent, "_EXIT_STATUS_POLL_INTERVAL_SECONDS", 0.01, raising=False)

    outcome = await asyncio.wait_for(
        agent.run_probes(
            agent.EvaluationTarget(host="cowrie", port=2222, username="root", password="x"),
            agent.AgentBudget(max_commands=10, max_seconds=60),
        ),
        timeout=3,
    )

    by_id = {o.probe_id: o for o in outcome.observations}
    assert outcome.module_status == "completed"
    assert by_id["p1"].fact_status == "unknown"
    assert by_id["p2"].fact_status == "unknown"
