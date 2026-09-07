import asyncio
import re

from app.db.models import FactStatus, ModuleStatus
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.sanity import Observation

# Ports the scan asks about. A port in this list that is not found is a real
# not_observed; a port outside it was never asked about and is never reported.
_EXPECTED_SERVICES = {"service.ssh": 2222, "service.telnet": 2223, "service.http": 80}

_OPEN_LINE = re.compile(r"^(?P<port>\d+)/tcp\s+open\s+(?P<rest>.*)$", re.MULTILINE)


async def _run_nmap(target: str, ports: str, timeout_seconds: int) -> str:
    """Run nmap against the fixed target. Separated so tests can replace it."""
    process = await asyncio.create_subprocess_exec(
        "nmap",
        "-sV",
        "-Pn",
        "-p",
        ports,
        target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        process.kill()
        raise
    return stdout.decode("utf-8", "replace")


def _unknown_observations() -> list[Observation]:
    return [
        Observation(
            probe_id=fact, establishes=fact, value=None, fact_status=FactStatus.UNKNOWN
        )
        for fact in _EXPECTED_SERVICES
    ]


async def scan(target: str, timeout_seconds: int) -> ModuleOutcome:
    """Scan the fixed honeypot target and report per-service facts.

    This establishes a comparison against an expected fingerprint set, NOT a
    claim that a service is "realistic" -- that judgement belongs to the
    evaluator, which sees this output as evidence.

    Failure model: a scan that could not complete (timeout or OS-level error
    launching nmap) must not be read as "no services exposed". Every expected
    fact is reported `unknown` in that case, never `not_observed` -- our own
    inability to look is not evidence against the honeypot. A port the scan
    actually looked for and did not find open is a genuine `not_observed`.
    """
    ports = ",".join(str(p) for p in _EXPECTED_SERVICES.values())
    try:
        output = await _run_nmap(target, ports, timeout_seconds)
    except TimeoutError:
        return ModuleOutcome(
            module="nmap",
            module_status=ModuleStatus.TIMEOUT,
            detail=f"nmap exceeded {timeout_seconds}s",
            observations=_unknown_observations(),
        )
    except OSError as exc:
        return ModuleOutcome(
            module="nmap",
            module_status=ModuleStatus.ERROR,
            detail=str(exc),
            observations=_unknown_observations(),
        )

    banners: dict[int, str] = {
        int(m.group("port")): m.group("rest").strip() for m in _OPEN_LINE.finditer(output)
    }

    observations = []
    for fact, port in _EXPECTED_SERVICES.items():
        banner = banners.get(port)
        observations.append(
            Observation(
                probe_id=fact,
                establishes=fact,
                value=banner,
                fact_status=FactStatus.OBSERVED if banner else FactStatus.NOT_OBSERVED,
            )
        )

    return ModuleOutcome(
        module="nmap", module_status=ModuleStatus.COMPLETED, observations=observations
    )
