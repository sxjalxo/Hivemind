import struct

import pytest

from app.config import get_settings
from app.models.event import HoneypotEvent
from app.services import replay

HEADER = struct.Struct("<iLiiLL")
SHA = "a" * 64
START = 1_760_000_000  # epoch seconds; the session's first event


def record(op: int, direction: int, stamp: float, data: bytes = b"") -> bytes:
    sec = int(stamp)
    usec = round((stamp - sec) * 1_000_000)
    return HEADER.pack(op, 0, len(data), direction, sec, usec) + data


def ttylog(opened: float) -> bytes:
    return (
        record(1, 0, opened)
        + record(3, 1, opened + 1, b"l")  # keystroke: skipped, the output echoes it
        + record(3, 2, opened + 1, b"ls\r\n")
        + record(3, 3, opened + 2, b"uname -a")  # exec command: nothing echoes it
        + record(3, 2, opened + 2.5, b"Linux\r\n")
        + record(2, 0, opened + 3)
    )


def test_parse_keeps_output_and_exec_commands_and_drops_keystrokes():
    opened, frames = replay.parse_ttylog(ttylog(100.0))
    assert opened == 100.0
    assert [text for _, text in frames] == ["ls\r\n", "$ uname -a\r\n", "Linux\r\n"]
    assert [t for t, _ in frames] == [101.0, 102.0, 102.5]


def test_parse_drops_a_torn_final_record():
    raw = ttylog(100.0) + HEADER.pack(3, 0, 50, 2, 104, 0) + b"short"
    _, frames = replay.parse_ttylog(raw)
    assert len(frames) == 3


def _event(action: str, offset: float, sha: str | None = None) -> HoneypotEvent:
    from datetime import UTC, datetime

    ts = datetime.fromtimestamp(START + offset, UTC).isoformat().replace("+00:00", "Z")
    body = {
        "id": f"e{offset}",
        "timestamp": ts,
        "source": {"ip": "203.0.113.9"},
        "destination": {},
        "event": {"action": action, "category": "session"},
        "network": {"protocol": "ssh"},
        "honeypot": {"id": "cowrie-01", "name": "cowrie-01"},
        "session": {"id": "s1"},
        "risk": {"score": 0, "level": "informational"},
    }
    if sha is not None:
        body["file"] = {"hash": {"sha256": sha}}
    return HoneypotEvent.model_validate(body)


@pytest.fixture
def tty_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("COWRIE_TTY_PATH", str(tmp_path))
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def _events(monkeypatch, events):
    async def fake(session_id):
        return events

    monkeypatch.setattr(replay.session_builder, "get_session_events", fake)


@pytest.mark.asyncio
async def test_unset_path_means_not_configured(monkeypatch):
    monkeypatch.setenv("COWRIE_TTY_PATH", "")
    get_settings.cache_clear()
    try:
        assert (await replay.build_replay("s1")).status == "not_configured"
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_a_session_without_log_closed_has_no_recording(tty_dir, monkeypatch):
    _events(monkeypatch, [_event("cowrie.session.connect", 0)])
    assert (await replay.build_replay("s1")).status == "no_recording"


@pytest.mark.asyncio
async def test_a_hash_that_is_not_64_hex_is_never_joined_onto_the_path(tty_dir, monkeypatch):
    (tty_dir.parent / "secret").write_bytes(ttylog(START))
    _events(monkeypatch, [_event("cowrie.log.closed", 10, "../secret")])
    assert (await replay.build_replay("s1")).status == "no_recording"


@pytest.mark.asyncio
async def test_a_deleted_recording_is_missing(tty_dir, monkeypatch):
    _events(monkeypatch, [_event("cowrie.log.closed", 10, SHA)])
    assert (await replay.build_replay("s1")).status == "missing"


@pytest.mark.asyncio
async def test_own_recording_plays_from_zero(tty_dir, monkeypatch):
    (tty_dir / SHA).write_bytes(ttylog(START + 0.5))
    _events(
        monkeypatch, [_event("cowrie.session.connect", 0), _event("cowrie.log.closed", 10, SHA)]
    )
    result = await replay.build_replay("s1")
    assert result.status == "ok"
    assert not result.shared and not result.truncated
    assert [f.t for f in result.frames] == [1.0, 2.0, 2.5]
    assert result.duration == 2.5


@pytest.mark.asyncio
async def test_a_recording_opened_outside_the_session_is_marked_shared(tty_dir, monkeypatch):
    # Cowrie keeps one file per distinct input: this session typed what one
    # did an hour earlier, so the file on disk is that session's.
    (tty_dir / SHA).write_bytes(ttylog(START - 3600))
    _events(
        monkeypatch, [_event("cowrie.session.connect", 0), _event("cowrie.log.closed", 10, SHA)]
    )
    result = await replay.build_replay("s1")
    assert result.status == "ok" and result.shared


@pytest.mark.asyncio
async def test_an_oversized_recording_plays_truncated(tty_dir, monkeypatch):
    monkeypatch.setattr(replay, "MAX_BYTES", 120)
    (tty_dir / SHA).write_bytes(ttylog(START))
    _events(
        monkeypatch, [_event("cowrie.session.connect", 0), _event("cowrie.log.closed", 10, SHA)]
    )
    result = await replay.build_replay("s1")
    assert result.truncated and 0 < len(result.frames) < 3
