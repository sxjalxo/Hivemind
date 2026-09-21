import asyncio
import contextlib
import re
from contextlib import asynccontextmanager

from app.db.models import FactStatus, ModuleStatus
from app.services.evaluation import container
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.sanity import Observation

# Anchored to the start of a line, deliberately.
#
# tcpdump writes one line per packet to stdout and its summary to stderr. Merged
# into a single pipe, the two interleave without synchronisation, so a partial
# packet line's trailing digits can abut the summary: `...tcp 470363` followed by
# `0 packets captured` reads as "4703630 packets captured". That was observed --
# 4.7 million packets reported for a four-second SSH session -- and it is the
# worst kind of wrong, because it arrives as a confident `observed` fact.
#
# The streams are kept apart at the source now (see `_spawn`); this anchor is the
# second line of defence. A fragment glued to the front of the summary no longer
# matches at all, which yields `unknown` -- we could not read the count -- rather
# than a fabricated number.
_PACKETS = re.compile(r"^\s*(\d+) packets captured", re.MULTILINE)


async def _spawn(interface: str, capture_container: str):
    """Start tcpdump inside the capture sidecar. Replaced in tests.

    `docker exec`, never `docker run`. Creating a container is the one Docker
    operation that is unconditionally equivalent to root on the host -- it
    permits `-v /:/host --privileged` with no exploit required -- and this was
    the only place in the application that needed one. The container is
    declared in docker-compose.yml instead, sharing the honeypot's network
    namespace, so `interface` is still the honeypot's own and the packets
    counted are genuinely its own.

    That also removed the `--net=container:` argument this function used to
    build, which is where a per-honeypot run could attach to the wrong
    honeypot's namespace: which namespace the capture sees is now a property
    of the compose declaration rather than of an argument assembled here.

    Packet lines go to stdout and are discarded -- only the count is wanted,
    and draining them would grow without bound on a busy interface. The
    summary goes to stderr, kept on its own pipe so nothing can interleave
    into it. See `_PACKETS`.
    """
    return await container.spawn_checked(
        [
            "docker",
            "exec",
            capture_container,
            "tcpdump",
            "-i",
            interface,
            "-n",
            "-q",
        ],
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )


async def _request_stop(process, capture_container: str | None) -> None:
    """Ask tcpdump to finish so it flushes its summary line.

    Signalling INSIDE the container, not the local process. `terminate()` only
    reaps the `docker exec` client: on Windows it is TerminateProcess, which
    never reaches tcpdump, so it exits without printing "N packets captured"
    and the module reports `unknown` for a capture that worked. `pkill -INT`
    reaches the process that is actually holding the count.

    `-x tcpdump` is an exact-name match, so it cannot catch anything else the
    sidecar happens to be running. It would signal a second concurrent tcpdump
    in the SAME sidecar -- there is never one, because a honeypot admits one
    run at a time (the advisory lock in `app.routers.evaluation`) and each
    honeypot has its own sidecar.

    `terminate()` still follows, to reap the client once its child is done.
    """
    if capture_container:
        with contextlib.suppress(OSError, container.DockerPolicyError):
            killer = await container.spawn_checked(
                ["docker", "exec", capture_container, "pkill", "-INT", "-x", "tcpdump"],
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

    `capture_container` is the SIDECAR to exec into -- the one compose
    declares with `network_mode: service:<honeypot>`. Which honeypot's traffic
    this sees is therefore a property of that declaration, not of an argument
    built here, which is what stops a run against one honeypot capturing
    another's. Instance state, not module state: two honeypots can be
    evaluated at once and each has its own sidecar.

    `capture_container` may be None, meaning no capture is configured for
    this target -- a generic honeypot that is a bare host or a VM has no
    sidecar. That case is handled HERE rather than by the caller choosing a
    different context manager, because the difference between "no capture was
    configured" and "a capture ran and failed" is a fact about capturing, and
    this is the module that owns those facts. The orchestrator used to carry a
    second null implementation and a ternary to pick between them, which put
    half of one concept in a file that has no other opinion about tcpdump.
    """

    def __init__(
        self, interface: str, timeout_seconds: int, capture_container: str | None
    ) -> None:
        self._interface = interface
        self._timeout_seconds = timeout_seconds
        self._capture_container = capture_container
        self._process = None
        self.outcome: ModuleOutcome | None = None

    async def start(self) -> None:
        if self._capture_container is None:
            # Not configured. `outcome` stays None, which is NOT an `unknown`
            # fact: a run with no capture made no claim about network
            # activity, which is different from having looked and failed.
            # Capturing on THIS host instead would watch an interface the
            # honeypot's traffic never crosses and report "0 packets" as a
            # confident `not_observed` for traffic that did occur.
            return
        try:
            self._process = await _spawn(self._interface, self._capture_container)
        except OSError as exc:
            # Could not even launch the capture. Our own inability to look is
            # not evidence that no traffic occurred -- leave the fact
            # unknown, not not_observed.
            self._process = None
            self.outcome = _unknown_outcome(str(exc))

    async def stop(self) -> ModuleOutcome | None:
        if self._capture_container is None:
            # Never configured; see `start`. No outcome, so the caller records
            # nothing and the run claims nothing about network activity.
            return None
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
                await _request_stop(self._process, self._capture_container)
            except ProcessLookupError:
                # tcpdump already exited on its own (interface disappeared,
                # permission revoked mid-run) -- a normal way for a capture
                # to end. Still drain whatever output is available.
                pass

            stdout, stderr = await asyncio.wait_for(
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

        # stderr carries the summary; stdout is checked too so a caller that
        # merges the streams (or a test that models one) still works.
        match = None
        for stream in (stderr, stdout):
            if not stream:
                continue
            match = _PACKETS.search(stream.decode("utf-8", "replace"))
            if match is not None:
                break

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
async def capture(
    interface: str, timeout_seconds: int, capture_container: str | None
):
    """Bracket the active evaluation window with a capture.

    `stop` runs in a finally so an exception in any stage of the evaluation
    -- the agent, the chain runner, anything -- cannot leave a tcpdump
    process running past the end of the run.

    `capture_container` is required rather than defaulted: a default is what
    let a run against one honeypot silently capture another's traffic.
    """
    cap = Capture(interface, timeout_seconds, capture_container)
    await cap.start()
    try:
        yield cap
    finally:
        await cap.stop()
