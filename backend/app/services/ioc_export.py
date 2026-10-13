"""Indicators in formats other tools ingest: STIX 2.1, a MISP event, a plain blocklist.

What goes out is deliberately narrower than what the Threat Intelligence page
shows, because an export is consumed by machines that ACT on it -- a firewall
blocks, an IDS alerts:

* Only IPs, URLs and file hashes. A username like `root` or a command like
  `uname -a` is a useful observation here and a disaster in someone's IDS,
  matching every ordinary login.
* No private, loopback or otherwise non-global address. Local test traffic
  arrives from the Docker gateway, and a blocklist containing it tells a
  firewall to block your own network.

Every exclusion is counted in the response, so an export never reads as the
whole picture when it is not. Provenance (OBSERVED vs CORRELATED) travels in
each exported object's description or comment.

Attacker-controlled strings go into STIX patterns, so they are escaped: a URL
containing `'` would otherwise close the pattern's string literal and change
what the pattern matches.
"""

import ipaddress
import json
import uuid
from collections import Counter
from datetime import UTC, datetime

from app.models.intel import Indicator, IocExport

EXPORTED_TYPES = ("ip", "url", "hash")

# A fixed namespace, so one indicator always gets the same STIX id: re-importing
# an export updates objects instead of duplicating them.
_NAMESPACE = uuid.UUID("6f1b8c3e-2d4a-5e9f-8a7b-1c2d3e4f5a6b")
_IDENTITY_ID = f"identity--{uuid.uuid5(_NAMESPACE, 'hivemind')}"

_HASH_ALGORITHMS = {32: ("MD5", "md5"), 40: ("SHA-1", "sha1"), 64: ("SHA-256", "sha256")}


def _stix_string(value: str) -> str:
    """Escape for a STIX pattern string literal (backslash first, then quote)."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _stix_time(value: str) -> str:
    """STIX timestamps are UTC with millisecond precision."""
    moment = datetime.fromisoformat(value).astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def exclusion_reason(indicator: Indicator) -> str | None:
    """Why this indicator stays out of every export, or None when it goes in. Pure."""
    if indicator.type not in EXPORTED_TYPES:
        return f"type:{indicator.type}"
    if indicator.type == "ip":
        try:
            if not ipaddress.ip_address(indicator.value).is_global:
                return "non-public-ip"
        except ValueError:
            return "unparseable-ip"
    if indicator.type == "hash" and len(indicator.value) not in _HASH_ALGORITHMS:
        return "unknown-hash-length"
    return None


def stix_pattern(indicator: Indicator) -> str:
    value = _stix_string(indicator.value)
    if indicator.type == "ip":
        kind = "ipv6-addr" if ":" in indicator.value else "ipv4-addr"
        return f"[{kind}:value = '{value}']"
    if indicator.type == "url":
        return f"[url:value = '{value}']"
    algorithm = _HASH_ALGORITHMS[len(indicator.value)][0]
    return f"[file:hashes.'{algorithm}' = '{value}']"


def _description(indicator: Indicator) -> str:
    sessions = len(indicator.session_ids)
    return (
        f"{indicator.source} by the Hivemind honeypot in {sessions} "
        f"{'session' if sessions == 1 else 'sessions'}."
    )


def to_stix(indicators: list[Indicator], now: datetime) -> dict:
    created = _stix_time(now.isoformat())
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": _IDENTITY_ID,
            "created": created,
            "modified": created,
            "name": "Hivemind honeypot",
            "identity_class": "system",
        }
    ]
    for indicator in indicators:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(_NAMESPACE, f'{indicator.type}:{indicator.value}')}",
                "created_by_ref": _IDENTITY_ID,
                "created": _stix_time(indicator.first_seen),
                "modified": _stix_time(indicator.last_seen),
                "name": f"{indicator.type}: {indicator.value}",
                "description": _description(indicator),
                "indicator_types": ["malicious-activity"],
                "pattern": stix_pattern(indicator),
                "pattern_type": "stix",
                "valid_from": _stix_time(indicator.first_seen),
                "confidence": round(indicator.confidence * 100),
                "labels": [f"hivemind:{indicator.source.lower()}"],
            }
        )
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def to_misp(indicators: list[Indicator], now: datetime) -> dict:
    attributes = []
    for indicator in indicators:
        if indicator.type == "ip":
            # The address connected TO the honeypot: a source, not a destination.
            kind, category = "ip-src", "Network activity"
        elif indicator.type == "url":
            kind, category = "url", "Network activity"
        else:
            kind, category = _HASH_ALGORITHMS[len(indicator.value)][1], "Payload delivery"
        attributes.append(
            {
                "type": kind,
                "category": category,
                "value": indicator.value,
                "to_ids": True,
                "comment": _description(indicator),
                "first_seen": indicator.first_seen,
                "last_seen": indicator.last_seen,
            }
        )
    return {
        "Event": {
            "info": "Hivemind honeypot indicators",
            "date": now.date().isoformat(),
            # 3 = low, 0 = initial analysis, 0 = your organisation only. A honeypot
            # export is raw collection, not a vetted assessment; whoever imports it
            # decides how far it travels.
            "threat_level_id": "3",
            "analysis": "0",
            "distribution": "0",
            "Attribute": attributes,
        }
    }


def to_blocklist(indicators: list[Indicator], now: datetime) -> str:
    lines = [
        "# Hivemind honeypot: public source addresses seen attacking the honeypot.",
        f"# Generated {_stix_time(now.isoformat())}. Review before enforcing.",
    ]
    lines += sorted({i.value for i in indicators if i.type == "ip"})
    return "\n".join(lines) + "\n"


def build_export(fmt: str, indicators: list[Indicator], now: datetime | None = None) -> IocExport:
    now = now or datetime.now(UTC)
    kept: list[Indicator] = []
    excluded: Counter[str] = Counter()
    for indicator in indicators:
        reason = exclusion_reason(indicator)
        if reason is None:
            kept.append(indicator)
        else:
            excluded[reason] += 1

    stamp = now.strftime("%Y%m%d-%H%M%S")
    if fmt == "stix":
        content = json.dumps(to_stix(kept, now), indent=2)
        filename, media_type = f"hivemind-iocs-{stamp}.stix.json", "application/stix+json"
        exported = len(kept)
    elif fmt == "misp":
        content = json.dumps(to_misp(kept, now), indent=2)
        filename, media_type = f"hivemind-iocs-{stamp}.misp.json", "application/json"
        exported = len(kept)
    else:  # blocklist: IPs only, by definition of what a blocklist is
        content = to_blocklist(kept, now)
        filename, media_type = f"hivemind-blocklist-{stamp}.txt", "text/plain"
        exported = sum(1 for i in kept if i.type == "ip")
        excluded.update(f"type:{i.type}" for i in kept if i.type != "ip")

    return IocExport(
        format=fmt,
        filename=filename,
        media_type=media_type,
        content=content,
        exported=exported,
        excluded=dict(sorted(excluded.items())),
    )
