"""Third-party IP reputation from AbuseIPDB. Opt-in: nothing happens without a key.

Everything here is THIRD-PARTY: what other AbuseIPDB users have reported about an
address, not anything this honeypot observed. It is returned and rendered as its
own kind of claim, and never feeds a risk score, a technique or an indicator.

What leaves the system: the attacker's IP address, and nothing else -- no
session, command or credential. Only PUBLIC addresses are sent; a private or
local address means nothing to AbuseIPDB and would leak our own network layout.

The API key is read from settings and sent only in the request header. It never
appears in a response, an error message or a log line.
"""

import ipaddress
import time
from datetime import UTC, datetime
from typing import Literal

import httpx

from app.config import get_settings
from app.serialization import CamelModel

_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

# The free tier allows 1,000 checks a day. A profile page re-renders often, so a
# successful answer is kept for a day; failures are never cached, so a fixed key
# or a reset quota takes effect on the next view.
# ponytail: per-process dict, lost on restart and not shared between workers.
# Move it to Postgres if a restart ever costs real quota.
_TTL_SECONDS = 24 * 3600
_cache: dict[str, tuple[float, "Reputation"]] = {}

Status = Literal[
    "ok", "not_configured", "not_public", "invalid_ip", "rejected", "rate_limited", "unavailable"
]


class Reputation(CamelModel):
    source: str = "AbuseIPDB"
    status: Status
    detail: str | None = None
    # 0-100: AbuseIPDB's confidence that the address is abusive. Their number, not ours.
    abuse_confidence: int | None = None
    total_reports: int | None = None
    distinct_reporters: int | None = None
    last_reported_at: str | None = None
    country_code: str | None = None
    isp: str | None = None
    usage_type: str | None = None
    domain: str | None = None
    is_tor: bool | None = None
    checked_at: str | None = None


def configured() -> bool:
    return bool(get_settings().abuseipdb_api_key)


def clear_cache() -> None:
    _cache.clear()


def _from_response(body: dict) -> Reputation:
    data = body.get("data") or {}
    return Reputation(
        status="ok",
        abuse_confidence=data.get("abuseConfidenceScore"),
        total_reports=data.get("totalReports"),
        distinct_reporters=data.get("numDistinctUsers"),
        last_reported_at=data.get("lastReportedAt"),
        country_code=data.get("countryCode"),
        isp=data.get("isp"),
        usage_type=data.get("usageType"),
        domain=data.get("domain"),
        is_tor=data.get("isTor"),
        checked_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )


async def lookup(ip: str, transport: httpx.AsyncBaseTransport | None = None) -> Reputation:
    """AbuseIPDB's view of one address. Never raises; every failure is a status."""
    settings = get_settings()
    if not settings.abuseipdb_api_key:
        return Reputation(
            status="not_configured",
            detail="Set ABUSEIPDB_API_KEY to enable third-party reputation lookups.",
        )
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return Reputation(status="invalid_ip", detail=f"{ip!r} is not an IP address.")
    if not address.is_global:
        return Reputation(
            status="not_public",
            detail="Private and local addresses are never sent to a third party.",
        )

    cached = _cache.get(ip)
    if cached and cached[0] > time.monotonic():
        return cached[1]

    try:
        async with httpx.AsyncClient(timeout=10, transport=transport) as client:
            response = await client.get(
                _ENDPOINT,
                params={"ipAddress": ip, "maxAgeInDays": settings.abuseipdb_max_age_days},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        # The exception text can carry the request URL but never headers, so the
        # key cannot leak through it; only the exception's type is kept anyway.
        return Reputation(
            status="unavailable", detail=f"AbuseIPDB unreachable ({type(exc).__name__})."
        )

    if response.status_code in (401, 403):
        return Reputation(status="rejected", detail="AbuseIPDB rejected the API key.")
    if response.status_code == 429:
        return Reputation(
            status="rate_limited", detail="AbuseIPDB's daily limit for this key is used up."
        )
    if response.status_code != 200:
        return Reputation(
            status="unavailable", detail=f"AbuseIPDB answered HTTP {response.status_code}."
        )
    try:
        result = _from_response(response.json())
    except ValueError:
        return Reputation(status="unavailable", detail="AbuseIPDB returned an unreadable answer.")

    _cache[ip] = (time.monotonic() + _TTL_SECONDS, result)
    return result
