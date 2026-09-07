import asyncio
import contextlib
import re
from contextlib import asynccontextmanager

from app.db.models import FactStatus, ModuleStatus
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.sanity import Observation

_PACKETS = re.compile(r"(\d+) packets captured")


async def _spawn(interface: str):
    """Start tcpdump on the evaluation interface only. Replaced in tests."""
    return await asyncio.create_subprocess_exec(
        "tcpdump",
        "-i",
        interface,
        "-n",
        "-q",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )


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
                self._process.terminate()
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
