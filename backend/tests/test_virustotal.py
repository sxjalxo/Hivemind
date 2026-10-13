"""VirusTotal lookups, against a fake VirusTotal: no network, no quota spent."""

import base64

import httpx
import pytest

from app.config import get_settings
from app.main import app
from app.models.intel import Indicator
from app.services import virustotal

KEY = "vt-test-key-do-not-leak"
SHA256 = "a" * 64

REPORT = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 41,
                "suspicious": 2,
                "harmless": 0,
                "undetected": 27,
            },
            "reputation": -55,
            "last_analysis_date": 1760000000,
        }
    }
}


def _ioc(type_: str, value: str) -> Indicator:
    return Indicator(
        id="00000000-0000-0000-0000-000000000000",
        type=type_,
        value=value,
        confidence=1.0,
        first_seen="2026-10-01T00:00:00Z",
        last_seen="2026-10-01T00:00:00Z",
        session_ids=[],
        source="OBSERVED",
        tags=[],
    )


class FakeVirusTotal(httpx.AsyncBaseTransport):
    def __init__(self, status: int = 200, body: dict | None = None) -> None:
        self.status, self.body, self.requests = status, REPORT if body is None else body, []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json=self.body)


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", KEY)
    get_settings.cache_clear()
    virustotal.clear_cache()
    yield
    virustotal.clear_cache()
    get_settings.cache_clear()


async def test_without_a_key_nothing_is_sent(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    get_settings.cache_clear()
    try:
        fake = FakeVirusTotal()
        assert (await virustotal.lookup(_ioc("hash", SHA256), fake)).status == "not_configured"
        assert fake.requests == []
    finally:
        get_settings.cache_clear()


async def test_usernames_commands_and_private_ips_are_never_sent(keyed) -> None:
    fake = FakeVirusTotal()
    assert (await virustotal.lookup(_ioc("username", "root"), fake)).status == "not_supported"
    # A command line can carry a password typed into the honeypot.
    assert (
        await virustotal.lookup(_ioc("command", "echo pw | passwd"), fake)
    ).status == "not_supported"
    assert (await virustotal.lookup(_ioc("ip", "172.19.0.1"), fake)).status == "not_public"
    assert fake.requests == []


async def test_a_hash_report_is_parsed_and_the_key_stays_in_the_header(keyed) -> None:
    fake = FakeVirusTotal()
    verdict = await virustotal.lookup(_ioc("hash", SHA256), fake)

    assert verdict.status == "ok"
    assert (verdict.malicious, verdict.engines, verdict.reputation) == (41, 70, -55)
    [request] = fake.requests
    assert request.method == "GET", "a report is read, never submitted"
    assert request.url.path == f"/api/v3/files/{SHA256}"
    assert request.headers["x-apikey"] == KEY
    assert KEY not in str(request.url) and KEY not in verdict.model_dump_json()


async def test_a_url_is_addressed_by_virustotals_unpadded_base64_id(keyed) -> None:
    url = "http://198.51.100.7/x.sh"
    fake = FakeVirusTotal()
    verdict = await virustotal.lookup(_ioc("url", url), fake)

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert fake.requests[0].url.path == f"/api/v3/urls/{url_id}"
    assert verdict.permalink == f"https://www.virustotal.com/gui/url/{url_id}"


async def test_never_seen_is_an_answer_and_cached_but_a_failure_is_not(keyed) -> None:
    unseen = FakeVirusTotal(status=404, body={})
    first = await virustotal.lookup(_ioc("hash", SHA256), unseen)
    await virustotal.lookup(_ioc("hash", SHA256), unseen)
    assert first.status == "not_found" and len(unseen.requests) == 1

    virustotal.clear_cache()
    limited = FakeVirusTotal(status=429, body={})
    assert (await virustotal.lookup(_ioc("hash", SHA256), limited)).status == "rate_limited"
    await virustotal.lookup(_ioc("hash", SHA256), limited)
    assert len(limited.requests) == 2


async def test_the_route_only_looks_up_indicators_this_system_extracted() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        unknown = await client.get(
            "/api/threat-intelligence/00000000-0000-0000-0000-000000000000/virustotal"
        )
        malformed = await client.get("/api/threat-intelligence/not-a-uuid/virustotal")
    assert unknown.status_code == 404 and malformed.status_code == 404
