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
