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
    """Simulates a shell channel that accepts input and then goes silent.

    The command's completion marker never arrives, which is what happens when
    the target stops responding mid-command. `recv` blocks for a bounded 5s
    stand-in for an indefinite wait, so code that reads without a deadline
    genuinely stalls and the test's outer timeout catches it as a real failure
    rather than letting it pass silently.
    """

    def __init__(self) -> None:
        self.sent: list[str] = []

    def send(self, data: str) -> int:
        self.sent.append(data)
        return len(data)

    def recv(self, size: int) -> bytes:
        # Chatters forever without ever emitting the completion marker. This
        # is the realistic shape of the failure -- the channel is alive, the
        # command simply never signals that it finished -- and it can only be
        # escaped by enforcing the deadline, not by noticing a closed socket.
        time.sleep(0.01)
        return b"partial output before the hang\r\n"

    def settimeout(self, value) -> None:
        return None

    def close(self) -> None:
        return None


class _HangingSession:
    """Shaped like the real `_Session`: a marker and a channel."""

    marker = "__hm_test__"

    def __init__(self) -> None:
        self.channel = _HangingChannel()

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
    monkeypatch.setattr(agent, "_READ_POLL_INTERVAL_SECONDS", 0.01, raising=False)

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


# --- shell output parsing -------------------------------------------------
#
# Cowrie is a terminal, not an exec channel: it echoes what we type, glues the
# prompt to the front of that echo (a prompt has no trailing newline), and
# wraps output in ANSI insert-mode toggles. These tests use raw strings
# captured from the real honeypot.


def _raw(marker: str, command: str, body: str, code: int) -> str:
    """Reproduce Cowrie's wire format for one command."""
    esc = chr(27)
    prompt = "root@med-ws-04:~# "
    out = f"{prompt}echo {marker}open{marker}\r\n{esc}[4l{marker}open{marker}\r\n{esc}[4h"
    out += f"{prompt}{command}\r\n"
    if body:
        out += f"{esc}[4l{body}\r\n{esc}[4h"
    out += f"{prompt}echo {marker}$?{marker}\r\n{esc}[4l{marker}{code}{marker}\r\n{esc}[4h"
    out += prompt
    return out


def test_shell_output_excludes_the_prompt_and_the_commands_own_echo() -> None:
    """The prompt arrives on the SAME line as the echo, so a naive line-equality
    check against the command never matches it and the echo leaks into the
    output."""
    raw = _raw("__hm_t__", "uname -a", "Linux med-ws-04 6.1.0-21-amd64", 0)

    assert agent._clean(raw, "uname -a", "__hm_t__") == "Linux med-ws-04 6.1.0-21-amd64"


def test_a_command_that_printed_nothing_cleans_to_nothing() -> None:
    """This is the one that matters for provenance.

    `cat /etc/os-release` genuinely prints nothing on this honeypot -- a real
    absence, and a real realism finding. If the prompt or the echo survives
    cleaning, the empty result becomes a non-empty string and run_probes reads
    it as OBSERVED: a gap in the honeypot silently reported as a fact about it.
    """
    raw = _raw("__hm_t__", "cat /etc/os-release", "", 0)

    assert agent._clean(raw, "cat /etc/os-release", "__hm_t__") == ""


def test_output_is_framed_by_markers_not_by_the_prompt() -> None:
    """A honeypot's prompt is one of the things an evaluation may find wrong,
    so it must never be what decides where output starts and stops. Anything
    before the opening marker belongs to the banner or a previous command."""
    esc = chr(27)
    raw = (
        "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY.\r\n"
        "leftover output from something earlier\r\n"
        + _raw("__hm_t__", "whoami", "root", 0)
    )

    assert agent._clean(raw, "whoami", "__hm_t__") == "root"


def test_a_nonzero_exit_with_output_is_still_parsed() -> None:
    raw = _raw("__hm_t__", "nosuchcommand", "-bash: nosuchcommand: command not found", 127)

    assert agent._clean(raw, "nosuchcommand", "__hm_t__") == (
        "-bash: nosuchcommand: command not found"
    )
