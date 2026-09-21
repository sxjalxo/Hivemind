import pytest

from app.services.evaluation.static import nmap


@pytest.mark.asyncio
async def test_a_timeout_yields_unknown_facts_not_absent_services(monkeypatch) -> None:
    # The decisive assertion for the whole failure model: a module that could
    # not run must not be readable as "no services exposed".
    async def _boom(*args, **kwargs):
        raise TimeoutError

    monkeypatch.setattr(nmap, "_run_nmap", _boom)

    outcome = await nmap.scan("cowrie", timeout_seconds=1, ssh_port=2222)

    assert outcome.module_status == "timeout"
    assert outcome.observations
    assert all(o.fact_status == "unknown" for o in outcome.observations)
    assert all(o.value is None for o in outcome.observations)


@pytest.mark.asyncio
async def test_a_completed_scan_marks_the_open_port_observed(monkeypatch) -> None:
    async def _fake(*args, **kwargs):
        # 2222/tcp: the honeypot's actual exposed SSH port (see docker-compose.yml),
        # matching _EXPECTED_SERVICES -- not the real-world default port 22.
        return "2222/tcp open ssh OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)\n"

    monkeypatch.setattr(nmap, "_run_nmap", _fake)

    outcome = await nmap.scan("cowrie", timeout_seconds=30, ssh_port=2222)
    facts = {o.establishes: o for o in outcome.observations}

    assert outcome.module_status == "completed"
    assert facts["service.ssh"].fact_status == "observed"
    assert "OpenSSH" in facts["service.ssh"].value
    # A port the scan looked for and did not find is a real negative.
    assert facts["service.http"].fact_status == "not_observed"


@pytest.mark.asyncio
async def test_the_scan_asks_about_the_targets_own_ssh_port(monkeypatch) -> None:
    """A honeypot's SSH port is per-honeypot; the scan's must follow it.

    `_EXPECTED_SERVICES` hardcoded 2222, so a honeypot mapped to 2322 in
    EVALUATION_TARGETS was scanned on a port nothing was listening on and
    scored `service.ssh: not_observed` -- a real deduction against `services`
    -- while the agent was logged into 2322 at that moment. The contradiction
    detector cannot catch it either: it only compares probes establishing the
    same fact, and no agent probe establishes `service.ssh`.
    """
    asked: list[str] = []

    async def _fake(target, ports, timeout_seconds):
        asked.append(ports)
        return "2322/tcp open ssh OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)\n"

    monkeypatch.setattr(nmap, "_run_nmap", _fake)

    outcome = await nmap.scan("cowrie", timeout_seconds=30, ssh_port=2322)
    facts = {o.establishes: o for o in outcome.observations}

    assert "2322" in asked[0]
    assert "2222" not in asked[0]
    # The open port found is the one we asked about, so this is `observed`
    # rather than the false negative the hardcoded port produced.
    assert facts["service.ssh"].fact_status == "observed"
    # Facts the scan establishes are unchanged -- only the port moved.
    assert set(facts) == set(nmap._EXPECTED_SERVICES)


@pytest.mark.asyncio
async def test_an_ssh_port_colliding_with_another_default_is_asked_once(
    monkeypatch,
) -> None:
    """`-p 80,2223,80` is legal but reads as a bug in a log."""
    asked: list[str] = []

    async def _fake(target, ports, timeout_seconds):
        asked.append(ports)
        return ""

    monkeypatch.setattr(nmap, "_run_nmap", _fake)

    await nmap.scan("cowrie", timeout_seconds=30, ssh_port=80)

    assert asked[0].split(",").count("80") == 1
