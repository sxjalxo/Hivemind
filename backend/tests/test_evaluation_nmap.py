import pytest

from app.services.evaluation.static import nmap


@pytest.mark.asyncio
async def test_a_timeout_yields_unknown_facts_not_absent_services(monkeypatch) -> None:
    # The decisive assertion for the whole failure model: a module that could
    # not run must not be readable as "no services exposed".
    async def _boom(*args, **kwargs):
        raise TimeoutError

    monkeypatch.setattr(nmap, "_run_nmap", _boom)

    outcome = await nmap.scan("cowrie", timeout_seconds=1)

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

    outcome = await nmap.scan("cowrie", timeout_seconds=30)
    facts = {o.establishes: o for o in outcome.observations}

    assert outcome.module_status == "completed"
    assert facts["service.ssh"].fact_status == "observed"
    assert "OpenSSH" in facts["service.ssh"].value
    # A port the scan looked for and did not find is a real negative.
    assert facts["service.http"].fact_status == "not_observed"
