import pytest

from app.seed.seeder import seed
from app.services.session_builder import (
    build_timeline,
    get_session,
    get_session_events,
    list_sessions,
)


@pytest.mark.asyncio
async def test_list_sessions_finds_all_six_seeded_sessions() -> None:
    await seed(reset=True)
    sessions = await list_sessions()
    ids = {s.id for s in sessions}

    assert {
        "seed-botnet-01",
        "seed-miner-01",
        "seed-persist-01",
        "seed-recon-01",
        "seed-brute-01",
        "seed-unmapped-01",
    } <= ids


@pytest.mark.asyncio
async def test_session_aggregates_commands_and_duration() -> None:
    await seed(reset=True)
    session = await get_session("seed-botnet-01")

    assert session is not None
    assert session.attacker_ip == "185.220.101.44"
    assert session.command_count == 7
    assert session.duration_seconds == 33
    assert session.protocol == "ssh"
    assert session.honeypot_id == "cowrie-01"


@pytest.mark.asyncio
async def test_unanalyzed_session_reports_no_invented_analysis() -> None:
    await seed(reset=True)
    session = await get_session("seed-recon-01")

    assert session is not None
    assert session.analysis_state == "not_analyzed"
    assert session.classification_chain == []
    assert session.mitre_technique_ids == []
    assert session.risk_score == 0
    assert session.risk == "informational"


@pytest.mark.asyncio
async def test_failed_bruteforce_has_zero_commands() -> None:
    await seed(reset=True)
    session = await get_session("seed-brute-01")

    assert session is not None
    assert session.command_count == 0
    assert session.username == "admin"


@pytest.mark.asyncio
async def test_timeline_kinds_are_derived_from_event_action() -> None:
    await seed(reset=True)
    timeline = await build_timeline("seed-botnet-01")
    kinds = [t.kind for t in timeline]

    assert kinds[0] == "connection"
    assert "auth" in kinds
    assert "command" in kinds
    assert "download" in kinds
    assert kinds[-1] == "disconnect"


@pytest.mark.asyncio
async def test_session_events_are_time_ordered() -> None:
    await seed(reset=True)
    events = await get_session_events("seed-botnet-01")

    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)


@pytest.mark.asyncio
async def test_list_sessions_filters_by_free_text_command() -> None:
    await seed(reset=True)
    sessions = await list_sessions(q="xmrig_setup")

    assert [s.id for s in sessions] == ["seed-miner-01"]


@pytest.mark.asyncio
async def test_get_session_returns_none_for_unknown_id() -> None:
    assert await get_session("no-such-session") is None
