import asyncio
import re
import secrets
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
    # What is at the other end -- see `app.config.HoneypotTarget.kind`.
    #
    # The default is the CONSERVATIVE value, not the common one. A caller
    # that forgets to carry the kind across gets a target treated as a real
    # machine: no destructive chain steps, no chain read-back. Defaulting to
    # "cowrie" would mean a forgotten field is what decides whether
    # `rm -rf /root/.ssh` runs for real, and the cost of the two mistakes is
    # not remotely symmetric.
    kind: str = "generic"

    @property
    def simulates_commands(self) -> bool:
        return self.kind == "cowrie"

    @property
    def has_own_event_log(self) -> bool:
        return self.kind == "cowrie"


class AgentBudget(BaseModel):
    max_commands: int
    max_seconds: int


# Commands run over an INTERACTIVE SHELL, not an exec channel.
#
# Cowrie accepts an `exec` request and then closes the channel: every form of
# it -- SSHClient.exec_command, and a raw Transport.open_session followed by
# exec_command -- fails with `SSHException: Channel closed.` before a single
# byte is readable. invoke_shell works and returns real output, so the shell
# is the only usable path against this target.
#
# A shell has no exit-status exchange, so each command is followed by a second
# line that echoes `$?` between two copies of a per-session marker. That marker
# is what terminates the read: waiting for a prompt instead would be guesswork,
# because the prompt of the system under test is precisely one of the things
# an evaluation is allowed to find wrong.
#
# The marker line is sent as its OWN command rather than appended with `;`, and
# that is load-bearing: chain verification reads commands back out of Cowrie's
# log and matches them against the declared step text. Appending anything to
# the command would change what Cowrie logs, and every chain would silently
# fail to verify.
PER_COMMAND_TIMEOUT_SECONDS = 20
_READ_POLL_INTERVAL_SECONDS = 0.05

# Cowrie emulates a terminal, so its output carries ANSI control sequences
# (insert-mode toggles wrapping each command's output) that the command never
# printed. They are stripped before anything is treated as a fact.
_ANSI_SEQUENCE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# A shell prompt is printed WITHOUT a trailing newline, so the terminal's echo
# of a command arrives as `<prompt># <command>` on one line. Stripping a
# leading prompt is therefore needed to recognise that echo -- but it is only
# ever a tidy-up: the output window itself is framed by markers, never by the
# prompt, because the prompt of the system under test is one of the things an
# evaluation is allowed to find wrong.
_PROMPT_PREFIX = re.compile(r"^\S+@\S+:\S*\s*[#$]\s*")


def _read_until(channel: paramiko.Channel, pattern: re.Pattern[str], deadline: float) -> tuple[str, re.Match[str] | None]:
    """Accumulate channel output until `pattern` matches or `deadline` passes.

    Returns whatever was read either way. A timeout is not an error here: the
    caller reports it as `unknown`, because a command we could not read to
    completion tells us nothing about the honeypot in either direction.
    """
    buffer = ""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        # Clamp every read to the time actually left. Checking the deadline
        # only BETWEEN reads would let one blocking recv overrun it by however
        # long the socket timeout happens to be -- the deadline has to bound
        # the read itself, not just the gaps between reads.
        try:
            channel.settimeout(min(_READ_POLL_INTERVAL_SECONDS, remaining))
        except OSError:
            pass
        try:
            chunk = channel.recv(65535)
        except TimeoutError:
            continue
        except OSError:
            break
        if not chunk:
            break
        buffer += chunk.decode("utf-8", "replace")
        match = pattern.search(buffer)
        if match is not None:
            return buffer, match
    return buffer, None


def _clean(raw: str, command: str, marker: str) -> str:
    """Reduce raw terminal output to what the command actually printed.

    Everything before the opening marker is the login banner or a previous
    command's tail; everything from the closing marker on is ours. Only the
    window between them can contain output, and framing it on markers rather
    than on the prompt is what keeps this correct against a honeypot whose
    prompt is unusual -- or deliberately misleading.

    Inside that window the terminal echoes each line we sent, and a prompt
    arrives on the same line as the echo because a prompt carries no trailing
    newline. Those echoes are matched by SUFFIX, so they are recognised
    whether or not a prompt was prepended and whatever that prompt looks like.
    """
    text = _ANSI_SEQUENCE.sub("", raw).replace("\r\n", "\n").replace("\r", "\n")

    # Frame on the markers. The opening marker is echoed twice -- once as the
    # command we sent, once as its result -- so take everything after the LAST
    # occurrence before the closing marker.
    opening = f"{marker}open{marker}"
    if opening in text:
        text = text.rsplit(opening, 1)[1]
    closing = re.search(re.escape(marker) + r"-?\d+" + re.escape(marker), text)
    if closing is not None:
        text = text[: closing.start()]

    command_text = command.strip()
    lines: list[str] = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped or marker in stripped:
            continue
        # Drop the terminal's echo of what we sent, with or without a prompt
        # glued to the front of it.
        bare = _PROMPT_PREFIX.sub("", stripped).strip()
        if bare == command_text or bare.startswith(f"echo {marker}"):
            continue
        if not bare:
            continue
        lines.append(bare)
    return "\n".join(lines).strip()


class _Session:
    """A live SSH session against the honeypot, backed by an interactive shell."""

    def __init__(self, target: EvaluationTarget) -> None:
        self._target = target
        self._client: paramiko.SSHClient | None = None
        self._channel: paramiko.Channel | None = None
        # A per-session nonce, not a fixed string. The honeypot is the system
        # under test and its output is what we are parsing, so a predictable
        # marker could be echoed back -- by accident or by a honeypot designed
        # to confuse an analyst -- and forge a command boundary.
        self.marker = f"__hm_{secrets.token_hex(8)}__"

    async def __aenter__(self) -> "_Session":
        def _connect() -> tuple[paramiko.SSHClient, paramiko.Channel]:
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
            channel = client.invoke_shell()
            channel.settimeout(_READ_POLL_INTERVAL_SECONDS)
            return client, channel

        self._client, self._channel = await asyncio.to_thread(_connect)
        await asyncio.to_thread(self._synchronise)
        return self

    def _synchronise(self) -> None:
        """Consume the login banner so it cannot be read as a command's output.

        Rather than sleep and hope, or guess at the prompt, this sends one
        marker line and reads up to it. Everything before it is the banner.
        """
        assert self._channel is not None
        marker_command = f"echo {self.marker}$?{self.marker}"
        self._channel.send(marker_command + "\n")
        _read_until(
            self._channel,
            re.compile(re.escape(self.marker) + r"(-?\d+)" + re.escape(self.marker)),
            time.monotonic() + PER_COMMAND_TIMEOUT_SECONDS,
        )

    async def __aexit__(self, *exc) -> bool:
        if self._channel is not None:
            await asyncio.to_thread(self._channel.close)
        if self._client is not None:
            await asyncio.to_thread(self._client.close)
        return False

    @property
    def client(self) -> paramiko.SSHClient:
        assert self._client is not None
        return self._client

    @property
    def channel(self) -> paramiko.Channel:
        assert self._channel is not None
        return self._channel


def _open_session(target: EvaluationTarget) -> _Session:
    """Build the session for one run. Replaced wholesale in tests so no test
    ever opens a real SSH connection."""
    return _Session(target)


async def _execute(session: _Session, command: str) -> tuple[str, int | None]:
    """Run one command over the session's shell, returning its output and exit
    status. Separated from run_probes so tests can replace it without a real
    SSH round trip.

    The command is written verbatim, then a second line echoes `$?` between two
    copies of the session marker. Reading stops at that marker, bounded by
    PER_COMMAND_TIMEOUT_SECONDS; if it never arrives we return whatever was
    read with exit_status=None, and the caller reports the fact `unknown`.
    Nothing is left blocked -- the read loop simply stops looking.
    """
    marker = session.marker
    done = re.compile(re.escape(marker) + r"(-?\d+)" + re.escape(marker))

    def _run() -> tuple[str, int | None]:
        channel = session.channel
        # Three lines: an opening marker to frame the output, the command
        # itself written verbatim, then the exit status between two markers.
        # The command MUST go out on its own line and unmodified -- chain
        # verification reads it back out of the honeypot's log and matches it
        # against the declared step text, so anything appended to it would
        # make every chain silently fail to verify.
        channel.send(f"echo {marker}open{marker}\n")
        channel.send(command + "\n")
        channel.send(f"echo {marker}$?{marker}\n")

        raw, match = _read_until(
            channel, done, time.monotonic() + PER_COMMAND_TIMEOUT_SECONDS
        )
        output = _clean(raw, command, marker)
        if match is None:
            return output, None
        return output, int(match.group(1))

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
                    # The command's completion marker never arrived within
                    # PER_COMMAND_TIMEOUT_SECONDS -- we gave up rather than
                    # block, so we did not determine this fact either way. Any
                    # partial output already read is not enough to call it
                    # observed: move on to the next probe rather than aborting
                    # the run.
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
