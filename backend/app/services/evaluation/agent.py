import asyncio
import time

import paramiko
from pydantic import BaseModel

from app.db.models import FactStatus, ModuleStatus
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.probes import Probe, load_probes
from app.services.evaluation.sanity import Observation


class EvaluationTarget(BaseModel):
    """The fixed honeypot endpoint to query.

    Constructed by the caller from settings only. There must be no code path
    from an HTTP request (or any other caller-supplied input) to this model
    -- the agent SSHes into whatever host it names, so a dynamic target
    would turn this into a general-purpose attack tool.
    """

    host: str
    port: int
    username: str
    password: str


class AgentBudget(BaseModel):
    max_commands: int
    max_seconds: int


# paramiko's Channel.recv_exit_status() blocks on an internal event with no
# timeout of its own -- its docstring warns it "may block forever" if the
# remote never completes the exit-status exchange. The `timeout=` passed to
# exec_command only bounds Channel.recv()/send() (i.e. stdout.read()), not
# this wait. Cowrie, the target here, is a deliberately imperfect SSH
# implementation that can leave a channel open without ever sending an exit
# status, so _execute polls exit_status_ready() against this wall-clock
# deadline instead of ever calling recv_exit_status() directly.
PER_COMMAND_TIMEOUT_SECONDS = 20
_EXIT_STATUS_POLL_INTERVAL_SECONDS = 0.05


class _Session:
    """A live SSH session against the honeypot."""

    def __init__(self, target: EvaluationTarget) -> None:
        self._target = target
        self._client: paramiko.SSHClient | None = None

    async def __aenter__(self) -> "_Session":
        def _connect() -> paramiko.SSHClient:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self._target.host,
                port=self._target.port,
                username=self._target.username,
                password=self._target.password,
                look_for_keys=False,
                allow_agent=False,
                timeout=20,
            )
            return client

        self._client = await asyncio.to_thread(_connect)
        return self

    async def __aexit__(self, *exc) -> bool:
        if self._client is not None:
            await asyncio.to_thread(self._client.close)
        return False

    @property
    def client(self) -> paramiko.SSHClient:
        assert self._client is not None
        return self._client


def _open_session(target: EvaluationTarget) -> _Session:
    """Build the session for one run. Replaced wholesale in tests so no test
    ever opens a real SSH connection."""
    return _Session(target)


async def _execute(session: _Session, command: str) -> tuple[str, int | None]:
    """Run one command over the session, returning its output and exit
    status. Separated from run_probes so tests can replace it without a real
    SSH round trip.

    The exit-status wait is bounded by PER_COMMAND_TIMEOUT_SECONDS: rather
    than call the blocking recv_exit_status(), we poll exit_status_ready()
    and give up once the deadline passes, returning exit_status=None. Nothing
    is left blocked -- the poll loop simply stops looking."""

    def _run() -> tuple[str, int | None]:
        _, stdout, _ = session.client.exec_command(command, timeout=20)
        output = stdout.read().decode("utf-8", "replace").strip()

        deadline = time.monotonic() + PER_COMMAND_TIMEOUT_SECONDS
        while not stdout.channel.exit_status_ready():
            if time.monotonic() >= deadline:
                return output, None
            time.sleep(_EXIT_STATUS_POLL_INTERVAL_SECONDS)
        return output, stdout.channel.recv_exit_status()

    return await asyncio.to_thread(_run)


async def run_probes(target: EvaluationTarget, budget: AgentBudget) -> ModuleOutcome:
    """Run every fixed probe against the honeypot, within a hard budget.

    Probes not reached because a budget ran out are reported `unknown`,
    never `not_observed`: we did not look, so we cannot say the fact is
    absent. Scoring must never read our own truncation as evidence against
    the honeypot.
    """
    probes: tuple[Probe, ...] = tuple(load_probes())
    observations: dict[str, Observation] = {
        p.id: Observation(
            probe_id=p.id, establishes=p.establishes, value=None, fact_status=FactStatus.UNKNOWN
        )
        for p in probes
    }

    status = ModuleStatus.COMPLETED
    detail: str | None = None
    started = time.monotonic()
    executed = 0

    try:
        async with _open_session(target) as session:
            for probe in probes:
                if executed >= budget.max_commands:
                    status = ModuleStatus.BUDGET_EXCEEDED
                    detail = f"command budget of {budget.max_commands} reached"
                    break
                if time.monotonic() - started > budget.max_seconds:
                    status = ModuleStatus.BUDGET_EXCEEDED
                    detail = f"time budget of {budget.max_seconds}s reached"
                    break

                output, exit_status = await _execute(session, probe.command)
                executed += 1
                if exit_status is None:
                    # The exit-status wait exceeded PER_COMMAND_TIMEOUT_SECONDS
                    # -- we gave up rather than block, so we did not determine
                    # this fact either way. Any partial output already read is
                    # not enough to call it observed: move on to the next
                    # probe rather than aborting the run.
                    fact_status = FactStatus.UNKNOWN
                elif output:
                    # The command told us something, whether or not it
                    # reported success -- a non-zero exit with output still
                    # observed a fact (e.g. a permission-denied message).
                    fact_status = FactStatus.OBSERVED
                elif exit_status == 0:
                    # Ran cleanly and found nothing: a genuine absence.
                    fact_status = FactStatus.NOT_OBSERVED
                else:
                    # Failed and told us nothing: we did not determine the
                    # fact, so it must not read as evidence of absence.
                    fact_status = FactStatus.UNKNOWN
                observations[probe.id] = Observation(
                    probe_id=probe.id,
                    establishes=probe.establishes,
                    value=output or None,
                    fact_status=fact_status,
                )
    except TimeoutError:
        status, detail = ModuleStatus.TIMEOUT, "ssh session timed out"
    except (OSError, paramiko.SSHException) as exc:
        status, detail = ModuleStatus.ERROR, str(exc)

    return ModuleOutcome(
        module="agent",
        module_status=status,
        detail=detail,
        observations=list(observations.values()),
    )
