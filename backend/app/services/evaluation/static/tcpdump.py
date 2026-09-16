import asyncio
import contextlib
import re
import uuid
from contextlib import asynccontextmanager

from app.config import get_settings
from app.db.models import FactStatus, ModuleStatus
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.sanity import Observation

_PACKETS = re.compile(r"(\d+) packets captured")

# Set by `_spawn` when the capture runs as a container, read by `_request_stop`.
# A capture is never concurrent with another within a run, and a stale name is
# harmless: `docker kill` on a container that is already gone just fails.
_container_name: str | None = None


async def _spawn(interface: str):
    """Start tcpdump on the evaluation interface only. Replaced in tests.

    With `evaluation_capture_image` set, tcpdump runs inside the honeypot
    container's OWN network namespace, so `interface` is the honeypot's
    interface. This is not a convenience: where the honeypot is reached through
    a published container port, a capture on the host (or in a WSL distro) sees
    zero packets and the module would report `not_observed` -- a confident
    claim that no traffic occurred, which is worse than reporting that we could
    not look. Measured on this machine: 0 packets in a WSL distro against 30 in
    the container's namespace, for the same SSH session.
    """
    global _container_name
    settings = get_settings()
    image = settings.evaluation_capture_image.strip()
    if not image:
        _container_name = None
        return await asyncio.create_subprocess_exec(
            "tcpdump",
            "-i",
            interface,
            "-n",
            "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

    _container_name = f"hivemind-capture-{uuid.uuid4().hex[:12]}"
    return await asyncio.create_subprocess_exec(
        "docker",
        "run",
        "--rm",
        "--name",
        _container_name,
        f"--net=container:{settings.evaluation_container_name}",
        image,
        "tcpdump",
        "-i",
        interface,
        "-n",
        "-q",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )


async def _request_stop(process) -> None:
    """Ask the capture to finish so tcpdump flushes its summary line.

    `process.terminate()` is the right thing for a local tcpdump on POSIX, but
    it is NOT enough for a containerised one on Windows: there `terminate()` is
    TerminateProcess, a hard kill of the local docker CLI, which never reaches
    tcpdump. It then exits without printing "N packets captured" and the module
    reports `unknown` for a capture that actually worked. Signalling the
    container itself gives tcpdump the interrupt it needs.
    """
    if _container_name:
        with contextlib.suppress(OSError):
            killer = await asyncio.create_subprocess_exec(
                "docker",
                "kill",
                "--signal=INT",
                _container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
    process.terminate()


def _unknown_outcome(detail: str) -> ModuleOutcome:
    return ModuleOutcome(
        module="tcpdump",
        module_status=ModuleStatus.ERROR,
        detail=detail,
        observations=[
            Observation(
                probe_id="network.activity",
                establishes="network.activity",
                value=None,
                fact_status=FactStatus.UNKNOWN,
            )
        ],
    )


class Capture:
    """Brackets the active evaluation window with a packet capture.

    This establishes ONLY that packets crossed the interface during the
    window -- not that the honeypot is plausible or convincing. That
    judgement belongs to the evaluator LLM, which consumes this module's
    output as one piece of evidence among several.
    """

    def __init__(self, interface: str, timeout_seconds: int) -> None:
        self._interface = interface
        self._timeout_seconds = timeout_seconds
        self._process = None
        self.outcome: ModuleOutcome | None = None

    async def start(self) -> None:
        try:
            self._process = await _spawn(self._interface)
        except OSError as exc:
            # Could not even launch the capture. Our own inability to look is
            # not evidence that no traffic occurred -- leave the fact
            # unknown, not not_observed.
            self._process = None
            self.outcome = _unknown_outcome(str(exc))

    async def stop(self) -> ModuleOutcome:
        if self._process is None:
            if self.outcome is None:
                self.outcome = _unknown_outcome("capture never started")
            return self.outcome

        # stop() must never raise. It runs in a `finally` alongside whatever
        # exception is propagating from the capture body (e.g. the agent
        # stage blowing up) -- if stop() itself raised, Python would replace
        # that exception with stop()'s, and the orchestrator would report
        # the wrong cause for the run's failure. Every failure mode here is
        # captured into the outcome instead.
        try:
            try:
                await _request_stop(self._process)
            except ProcessLookupError:
                # tcpdump already exited on its own (interface disappeared,
                # permission revoked mid-run) -- a normal way for a capture
                # to end. Still drain whatever output is available.
                pass

            stdout, _ = await asyncio.wait_for(
                self._process.communicate(), timeout=self._timeout_seconds
            )
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                self._process.kill()
            self.outcome = ModuleOutcome(
                module="tcpdump",
                module_status=ModuleStatus.TIMEOUT,
                detail=f"tcpdump drain exceeded {self._timeout_seconds}s",
                observations=[
                    Observation(
                        probe_id="network.activity",
                        establishes="network.activity",
                        value=None,
                        fact_status=FactStatus.UNKNOWN,
                    )
                ],
            )
            return self.outcome
        except Exception as exc:  # noqa: BLE001 - must not propagate, see above
            self.outcome = _unknown_outcome(f"failed to stop tcpdump: {exc}")
            return self.outcome

        text = stdout.decode("utf-8", "replace")
        match = _PACKETS.search(text)

        if match is None:
            self.outcome = _unknown_outcome("no packet count in tcpdump output")
            return self.outcome

        value = match.group(1)
        # Establishes only that packets crossed the interface during the
        # window -- not that the environment is plausible.
        fact_status = FactStatus.OBSERVED if int(value) > 0 else FactStatus.NOT_OBSERVED

        self.outcome = ModuleOutcome(
            module="tcpdump",
            module_status=ModuleStatus.COMPLETED,
            observations=[
                Observation(
                    probe_id="network.activity",
                    establishes="network.activity",
                    value=value,
                    fact_status=fact_status,
                )
            ],
        )
        return self.outcome


@asynccontextmanager
async def capture(interface: str, timeout_seconds: int):
    """Bracket the active evaluation window with a capture.

    `stop` runs in a finally so an exception in any stage of the evaluation
    -- the agent, the chain runner, anything -- cannot leave a tcpdump
    process running past the end of the run.
    """
    cap = Capture(interface, timeout_seconds)
    await cap.start()
    try:
        yield cap
    finally:
        await cap.stop()
