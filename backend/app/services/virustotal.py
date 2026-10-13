"""Third-party verdicts from VirusTotal for extracted indicators. Opt-in.

Like `reputation`, everything here is THIRD-PARTY: what antivirus engines and
VirusTotal's community say, not what this honeypot observed. It feeds nothing.

Three rules that make it safe to expose:

* **By indicator id, never by arbitrary value.** The route looks an indicator up
  in our own table first, so only something this system extracted can be
  checked. A value-taking endpoint would make the API key a free VirusTotal
  proxy for anyone who can reach the API.
* **Read-only.** Only GET of an existing report. Nothing is ever SUBMITTED:
  submitting a URL or file publishes it to VirusTotal's community, which is not
  a decision a page view should make.
* **Only what is safe to send.** Hashes, URLs and public IPs. Never usernames or
  commands (a command line can carry a password typed into the honeypot), never
  a private address.

The free API allows 4 requests a minute and 500 a day, so lookups are on demand
(one click per indicator) and answers -- including "VirusTotal has never seen
this" -- are cached for a day. Failures are never cached.
"""

import base64
import ipaddress
import time
from datetime import UTC, datetime
from typing import Literal

import httpx

from app.config import get_settings
from app.models.intel import Indicator
from app.serialization import CamelModel

_API = "https://www.virustotal.com/api/v3"
_TTL_SECONDS = 24 * 3600
# ponytail: per-process dict, like `reputation`. Postgres if quota ever bites.
_cache: dict[tuple[str, str], tuple[float, "VirusTotalVerdict"]] = {}

Status = Literal[
    "ok", "not_found", "not_configured", "not_supported", "not_public",
    "rejected", "rate_limited", "unavailable",
]  # fmt: skip


class VirusTotalVerdict(CamelModel):
    source: str = "VirusTotal"
    status: Status
    detail: str | None = None
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    undetected: int | None = None
    # Engines that returned any verdict; `malicious` out of this is the headline.
    engines: int | None = None
    reputation: int | None = None
    last_analysis_at: str | None = None
    # A link a human can open, never containing the key.
    permalink: str | None = None
    checked_at: str | None = None


def clear_cache() -> None:
    _cache.clear()


def _path_for(indicator: Indicator) -> tuple[str, str] | VirusTotalVerdict:
    """(API path, GUI link) for an indicator, or the reason it is not sent. Pure."""
    value = indicator.value
    if indicator.type == "hash":
        return f"/files/{value}", f"https://www.virustotal.com/gui/file/{value}"
    if indicator.type == "url":
        # VirusTotal's URL id: unpadded URL-safe base64 of the URL itself.
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"/urls/{url_id}", f"https://www.virustotal.com/gui/url/{url_id}"
    if indicator.type == "ip":
        try:
            if not ipaddress.ip_address(value).is_global:
                return VirusTotalVerdict(
                    status="not_public",
                    detail="Private and local addresses are never sent to a third party.",
                )
        except ValueError:
            return VirusTotalVerdict(status="not_supported", detail="Not a valid IP address.")
        return f"/ip_addresses/{value}", f"https://www.virustotal.com/gui/ip-address/{value}"
    return VirusTotalVerdict(
        status="not_supported",
        detail=f"A {indicator.type} indicator is never sent to VirusTotal.",
    )


def _from_report(body: dict, permalink: str) -> VirusTotalVerdict:
    attributes = (body.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    analysed = attributes.get("last_analysis_date")
    return VirusTotalVerdict(
        status="ok",
        malicious=stats.get("malicious"),
        suspicious=stats.get("suspicious"),
        harmless=stats.get("harmless"),
        undetected=stats.get("undetected"),
        engines=sum(v for v in stats.values() if isinstance(v, int)) or None,
        reputation=attributes.get("reputation"),
        last_analysis_at=(
            datetime.fromtimestamp(analysed, UTC).isoformat().replace("+00:00", "Z")
            if isinstance(analysed, int)
            else None
        ),
        permalink=permalink,
        checked_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )


async def lookup(
    indicator: Indicator, transport: httpx.AsyncBaseTransport | None = None
) -> VirusTotalVerdict:
    """VirusTotal's report for one indicator. Never raises; every failure is a status."""
    settings = get_settings()
    if not settings.virustotal_api_key:
        return VirusTotalVerdict(
            status="not_configured",
            detail="Set VIRUSTOTAL_API_KEY to enable VirusTotal lookups.",
        )
    target = _path_for(indicator)
    if isinstance(target, VirusTotalVerdict):
        return target
    path, permalink = target

    key = (indicator.type, indicator.value)
    cached = _cache.get(key)
    if cached and cached[0] > time.monotonic():
        return cached[1]

    try:
        async with httpx.AsyncClient(timeout=15, transport=transport) as client:
            response = await client.get(
                _API + path,
                headers={"x-apikey": settings.virustotal_api_key, "Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        return VirusTotalVerdict(
            status="unavailable", detail=f"VirusTotal unreachable ({type(exc).__name__})."
        )

    if response.status_code == 404:
        result = VirusTotalVerdict(
            status="not_found",
            detail="VirusTotal has no report for this. Nothing was submitted to it.",
            permalink=permalink,
            checked_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
    elif response.status_code in (401, 403):
        return VirusTotalVerdict(status="rejected", detail="VirusTotal rejected the API key.")
    elif response.status_code == 429:
        return VirusTotalVerdict(
            status="rate_limited",
            detail="VirusTotal's rate limit was hit (free tier: 4 a minute, 500 a day).",
        )
    elif response.status_code != 200:
        return VirusTotalVerdict(
            status="unavailable", detail=f"VirusTotal answered HTTP {response.status_code}."
        )
    else:
        try:
            result = _from_report(response.json(), permalink)
        except ValueError:
            return VirusTotalVerdict(
                status="unavailable", detail="VirusTotal returned an unreadable answer."
            )

    _cache[key] = (time.monotonic() + _TTL_SECONDS, result)
    return result
