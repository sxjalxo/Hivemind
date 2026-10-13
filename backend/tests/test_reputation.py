"""AbuseIPDB lookups, against a fake AbuseIPDB: no network, no quota spent."""

import httpx
import pytest

from app.config import get_settings
from app.services import reputation

KEY = "test-key-do-not-leak"
PUBLIC = "185.220.101.44"

OK_BODY = {
    "data": {
        "ipAddress": PUBLIC,
        "abuseConfidenceScore": 100,
        "totalReports": 812,
        "numDistinctUsers": 190,
        "lastReportedAt": "2026-10-12T10:00:00+00:00",
        "countryCode": "DE",
        "isp": "Example Hosting",
        "usageType": "Data Center/Web Hosting/Transit",
        "domain": "example.net",
        "isTor": True,
    }
}


class FakeAbuseIPDB(httpx.AsyncBaseTransport):
    def __init__(self, status: int = 200, body: dict | None = None) -> None:
        self.status, self.body, self.requests = status, body or OK_BODY, []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json=self.body)


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", KEY)
    get_settings.cache_clear()
    reputation.clear_cache()
    yield
    reputation.clear_cache()
    get_settings.cache_clear()


@pytest.fixture
def unkeyed(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def test_without_a_key_nothing_is_sent(unkeyed) -> None:
    fake = FakeAbuseIPDB()
    result = await reputation.lookup(PUBLIC, transport=fake)
    assert result.status == "not_configured"
    assert fake.requests == []


async def test_a_private_or_invalid_address_is_never_sent(keyed) -> None:
    fake = FakeAbuseIPDB()
    assert (await reputation.lookup("172.19.0.1", transport=fake)).status == "not_public"
    assert (await reputation.lookup("127.0.0.1", transport=fake)).status == "not_public"
    assert (await reputation.lookup("not-an-ip", transport=fake)).status == "invalid_ip"
    assert fake.requests == []


async def test_a_report_is_parsed_and_the_key_goes_only_in_the_header(keyed) -> None:
    fake = FakeAbuseIPDB()
    result = await reputation.lookup(PUBLIC, transport=fake)

    assert result.status == "ok"
    assert (result.abuse_confidence, result.total_reports, result.distinct_reporters) == (
        100,
        812,
        190,
    )
    assert result.is_tor is True and result.source == "AbuseIPDB"
    [request] = fake.requests
    assert request.headers["Key"] == KEY
    assert request.url.params["ipAddress"] == PUBLIC
    assert KEY not in str(request.url)
    assert KEY not in result.model_dump_json()


async def test_an_answer_is_cached_but_a_failure_is_not(keyed) -> None:
    good = FakeAbuseIPDB()
    await reputation.lookup(PUBLIC, transport=good)
    await reputation.lookup(PUBLIC, transport=good)
    assert len(good.requests) == 1, "the second view must come from the cache"

    reputation.clear_cache()
    refused = FakeAbuseIPDB(status=401, body={"errors": []})
    first = await reputation.lookup(PUBLIC, transport=refused)
    await reputation.lookup(PUBLIC, transport=refused)
    assert first.status == "rejected"
    assert len(refused.requests) == 2, "a rejected key must be retried once it is fixed"


@pytest.mark.parametrize(
    ("status", "expected"),
    [(401, "rejected"), (403, "rejected"), (429, "rate_limited"), (500, "unavailable")],
)
async def test_failures_become_statuses_without_the_key(keyed, status, expected) -> None:
    result = await reputation.lookup(PUBLIC, transport=FakeAbuseIPDB(status=status, body={}))
    assert result.status == expected
    assert result.abuse_confidence is None
    assert KEY not in (result.detail or "")
