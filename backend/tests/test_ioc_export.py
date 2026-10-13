"""IOC export. Pure functions: no stack needed."""

import json
import re
from datetime import UTC, datetime

from app.models.intel import Indicator
from app.services.ioc_export import build_export, exclusion_reason, stix_pattern

NOW = datetime(2026, 10, 12, 18, 0, 0, tzinfo=UTC)
SHA256 = "a" * 64


def _ioc(type_: str, value: str, source: str = "OBSERVED") -> Indicator:
    return Indicator(
        id=f"{type_}-{value}",
        type=type_,
        value=value,
        confidence=0.9,
        first_seen="2026-10-01T10:00:00.123456Z",
        last_seen="2026-10-02T11:30:00Z",
        session_ids=["s1", "s2"],
        source=source,
        tags=[],
    )


MIXED = [
    _ioc("ip", "185.220.101.44"),
    _ioc("ip", "172.19.0.1"),  # the Docker gateway: local test traffic
    _ioc("url", "http://198.51.100.7/x.sh", "CORRELATED"),
    _ioc("hash", SHA256),
    _ioc("username", "root"),
    _ioc("command", "uname -a"),
    _ioc("command", "wget http://x"),
]


def test_only_public_ips_urls_and_known_hashes_leave_the_system():
    assert exclusion_reason(_ioc("ip", "185.220.101.44")) is None
    assert exclusion_reason(_ioc("ip", "172.19.0.1")) == "non-public-ip"
    assert exclusion_reason(_ioc("ip", "127.0.0.1")) == "non-public-ip"
    assert exclusion_reason(_ioc("ip", "not-an-ip")) == "unparseable-ip"
    assert exclusion_reason(_ioc("username", "root")) == "type:username"
    assert exclusion_reason(_ioc("command", "uname -a")) == "type:command"
    assert exclusion_reason(_ioc("hash", "abc")) == "unknown-hash-length"


def test_every_exclusion_is_counted_so_an_export_never_reads_as_complete():
    export = build_export("stix", MIXED, NOW)
    assert export.exported == 3
    assert export.excluded == {"non-public-ip": 1, "type:command": 2, "type:username": 1}


def test_an_attacker_quote_cannot_break_out_of_a_stix_pattern():
    pattern = stix_pattern(_ioc("url", "http://x/a' OR [ipv4-addr:value = '1.1.1.1"))
    # Exactly one string literal: every quote inside the value is escaped.
    body = pattern[len("[url:value = '") : -len("']")]
    assert re.search(r"(?<!\\)'", body) is None
    backslash = stix_pattern(_ioc("url", "http://x/a\\'b"))
    assert backslash == "[url:value = 'http://x/a\\\\\\'b']"


def test_patterns_name_the_right_object_and_hash_algorithm():
    assert stix_pattern(_ioc("ip", "2001:db8::1")) == "[ipv6-addr:value = '2001:db8::1']"
    assert stix_pattern(_ioc("hash", SHA256)) == f"[file:hashes.'SHA-256' = '{SHA256}']"
    assert stix_pattern(_ioc("hash", "b" * 32)).startswith("[file:hashes.'MD5'")


def test_stix_bundle_has_the_required_fields_and_stable_ids():
    first = json.loads(build_export("stix", MIXED, NOW).content)
    again = json.loads(build_export("stix", MIXED, NOW).content)
    indicators = [o for o in first["objects"] if o["type"] == "indicator"]

    assert first["type"] == "bundle"
    for o in indicators:
        for field in (
            "spec_version",
            "id",
            "created",
            "modified",
            "pattern",
            "pattern_type",
            "valid_from",
        ):
            assert field in o, field
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", o["created"])
    # Same indicator, same id: re-importing updates instead of duplicating.
    assert [o["id"] for o in indicators] == [
        o["id"] for o in again["objects"] if o["type"] == "indicator"
    ]
    assert any("CORRELATED" in o["description"] for o in indicators)


def test_misp_marks_attacker_addresses_as_sources_and_typed_hashes():
    attributes = json.loads(build_export("misp", MIXED, NOW).content)["Event"]["Attribute"]
    types = {(a["type"], a["value"]) for a in attributes}
    assert ("ip-src", "185.220.101.44") in types
    assert ("sha256", SHA256) in types
    assert all(a["to_ids"] for a in attributes)


def test_the_blocklist_is_public_addresses_only():
    export = build_export("blocklist", MIXED, NOW)
    entries = [line for line in export.content.splitlines() if not line.startswith("#")]
    assert entries == ["185.220.101.44"]
    assert export.exported == 1
    assert export.excluded["type:url"] == 1 and export.excluded["type:hash"] == 1
