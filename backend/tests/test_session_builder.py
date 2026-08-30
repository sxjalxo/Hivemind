import pytest

from app.config import get_settings
from app.es.client import get_es
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


# ---------------------------------------------------------------------------
# Timeline event-kind classification.
#
# The seed corpus only contains the handful of Cowrie eventids the classifier
# already knows, so it cannot exercise the fallback path at all. A real SSH
# connection emits several more (`cowrie.client.version`, `.kex`, `.size`,
# `cowrie.session.params`), and every one of them used to fall through to the
# "command" default and be rendered as something the attacker typed. These
# tests index a session shaped like live traffic so the fallback is covered.
# ---------------------------------------------------------------------------

_KINDS_SESSION = "test-timeline-kinds-01"


def _kind_fixture_doc(
    action: str,
    timestamp: str,
    *,
    category: str = "other",
    command: str | None = None,
) -> dict:
    doc: dict = {
        "@timestamp": timestamp,
        "event": {"action": action, "category": category},
        "session": {"id": _KINDS_SESSION},
        "source": {"ip": "203.0.113.9", "port": 40001},
        "destination": {"ip": "172.19.0.3", "port": 2222},
        "honeypot": {"id": "cowrie-01", "name": "Cowrie SSH (med-ws-04)"},
        "network": {"protocol": "ssh"},
        "labels": {"seeded": False},
        "risk": {"score": 0, "level": "informational"},
    }
    if command is not None:
        doc["process"] = {"command_line": command}
    return doc


_KIND_FIXTURE = {
    "tk-connect": _kind_fixture_doc("cowrie.session.connect", "2026-08-30T09:00:00.000Z"),
    "tk-version": _kind_fixture_doc("cowrie.client.version", "2026-08-30T09:00:00.100Z"),
    "tk-kex": _kind_fixture_doc("cowrie.client.kex", "2026-08-30T09:00:00.200Z"),
    "tk-login": _kind_fixture_doc("cowrie.login.success", "2026-08-30T09:00:00.300Z"),
    "tk-params": _kind_fixture_doc("cowrie.session.params", "2026-08-30T09:00:00.400Z"),
    "tk-cmd": _kind_fixture_doc(
        "cowrie.command.input",
        "2026-08-30T09:00:01.000Z",
        category="process",
        command="uname -a",
    ),
    "tk-failed": _kind_fixture_doc(
        "cowrie.command.failed",
        "2026-08-30T09:00:01.100Z",
        category="process",
        command="./malicious_script",
    ),
    "tk-unknown": _kind_fixture_doc("cowrie.some.future.eventid", "2026-08-30T09:00:02.000Z"),
    "tk-closed": _kind_fixture_doc("cowrie.session.closed", "2026-08-30T09:00:03.000Z"),
}


async def _index_kind_fixture() -> None:
    es = get_es()
    index = get_settings().es_index
    for doc_id, doc in _KIND_FIXTURE.items():
        await es.index(index=index, id=doc_id, document=doc, refresh=True)


async def _delete_kind_fixture() -> None:
    await get_es().delete_by_query(
        index=get_settings().es_index,
        query={"term": {"session.id": _KINDS_SESSION}},
        refresh=True,
    )


@pytest.mark.asyncio
async def test_timeline_does_not_present_ssh_protocol_metadata_as_a_command() -> None:
    await _index_kind_fixture()
    try:
        kinds = {e.id: e.kind for e in await build_timeline(_KINDS_SESSION)}

        assert kinds["tk-version"] == "protocol"
        assert kinds["tk-kex"] == "protocol"
        assert kinds["tk-params"] == "protocol"
    finally:
        await _delete_kind_fixture()


@pytest.mark.asyncio
async def test_timeline_kind_for_an_unrecognised_event_action_is_other() -> None:
    await _index_kind_fixture()
    try:
        kinds = {e.id: e.kind for e in await build_timeline(_KINDS_SESSION)}

        assert kinds["tk-unknown"] == "other"
    finally:
        await _delete_kind_fixture()


@pytest.mark.asyncio
async def test_timeline_command_rows_match_the_session_command_count() -> None:
    await _index_kind_fixture()
    try:
        session = await get_session(_KINDS_SESSION)
        timeline = await build_timeline(_KINDS_SESSION)

        assert session is not None
        assert session.command_count == 1
        assert [e.id for e in timeline if e.kind == "command"] == ["tk-cmd"]
    finally:
        await _delete_kind_fixture()


@pytest.mark.asyncio
async def test_timeline_labels_only_the_connect_event_with_the_source_ip() -> None:
    await _index_kind_fixture()
    try:
        labels = {e.id: e.label for e in await build_timeline(_KINDS_SESSION)}

        assert labels["tk-connect"] == "Connection from 203.0.113.9"
        assert labels["tk-kex"] == "cowrie.client.kex"
    finally:
        await _delete_kind_fixture()


@pytest.mark.asyncio
async def test_timeline_does_not_repeat_the_event_action_as_label_and_detail() -> None:
    await _index_kind_fixture()
    try:
        rows = {e.id: e for e in await build_timeline(_KINDS_SESSION)}

        # Protocol and unrecognised rows have no friendlier label than the raw
        # eventid, so echoing it into `detail` renders the same string twice.
        assert rows["tk-kex"].detail is None
        assert rows["tk-unknown"].detail is None
        # Rows whose label is something else still name the action.
        assert rows["tk-connect"].detail == "cowrie.session.connect"
        assert rows["tk-failed"].detail == "cowrie.command.failed"
    finally:
        await _delete_kind_fixture()
