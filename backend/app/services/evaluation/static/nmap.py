import asyncio
import re

from app.db.models import FactStatus, ModuleStatus
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.sanity import Observation

# Ports the scan asks about. A port in this list that is not found is a real
# not_observed; a port outside it was never asked about and is never reported.
#
# `service.ssh`'s value here is only a DEFAULT. The port actually scanned comes
# from the target (see `_expected_services`), because since per-honeypot
# targets a honeypot's SSH port is per-honeypot too. Scanning 2222 while the
# agent logs in on 2322 reported `service.ssh: not_observed` -- a real
# deduction against the `services` score -- for a service that was up and that
# we were talking to at that moment. Nothing catches it downstream either: the
# contradiction detector only compares probes establishing the SAME fact, and
# no agent probe establishes `service.ssh`.
#
# ponytail: telnet and http stay fixed, because nothing in `HoneypotTarget`
# describes them -- there is no per-honeypot value to read. Give them target
# fields if a second honeypot ever moves them.
_EXPECTED_SERVICES = {"service.ssh": 2222, "service.telnet": 2223, "service.http": 80}


def _expected_services(ssh_port: int) -> dict[str, int]:
    """`_EXPECTED_SERVICES` with the target's real SSH port substituted in.

    Keys are unchanged, so which FACTS a scan establishes is still fixed by
    `_EXPECTED_SERVICES` and still hashed into the evaluation-config
    fingerprint. Only the port behind `service.ssh` moves, and that already
    moves `honeypot_fingerprint` (`fingerprints.Target.ssh_port`) -- which is
    the right fingerprint for it: pointing at a honeypot listening elsewhere
    changes what is under test, not the question being asked of it.
    """
    return {**_EXPECTED_SERVICES, "service.ssh": ssh_port}


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


async def scan(target: str, timeout_seconds: int, ssh_port: int) -> ModuleOutcome:
    """Scan the fixed honeypot target and report per-service facts.

    `ssh_port` is required, not defaulted: a default is exactly what made this
    module keep scanning 2222 after per-honeypot targets let a honeypot listen
    somewhere else. See `_expected_services`.

    This establishes a comparison against an expected fingerprint set, NOT a
    claim that a service is "realistic" -- that judgement belongs to the
    evaluator, which sees this output as evidence.

    Failure model: a scan that could not complete (timeout or OS-level error
    launching nmap) must not be read as "no services exposed". Every expected
    fact is reported `unknown` in that case, never `not_observed` -- our own
    inability to look is not evidence against the honeypot. A port the scan
    actually looked for and did not find open is a genuine `not_observed`.
    """
    expected = _expected_services(ssh_port)
    # `dict.values()` can repeat -- a honeypot whose SSH port collides with
    # the telnet or http default would ask nmap for the same port twice.
    # Harmless to nmap, but `-p 2223,2223,80` in a log reads like a bug.
    ports = ",".join(str(p) for p in dict.fromkeys(expected.values()))
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
    for fact, port in expected.items():
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
