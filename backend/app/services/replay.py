"""Terminal replay of a session from Cowrie's TTY log (checklist item 10).

Cowrie writes each channel's terminal traffic to a binary log and, when the
channel closes, renames it to the SHA-256 of its INPUT bytes and emits
`cowrie.log.closed` with that hash (indexed as `file.hash.sha256`). The
recordings directory is a volume the backend mounts read-only at
`COWRIE_TTY_PATH`; unset, the feature is off.

Because files are keyed by input alone, a session that types exactly what an
earlier one typed gets no file of its own: Cowrie deletes it and points at
the existing one. The recording's own open timestamp then lies outside the
session, which is how `shared` is detected -- from the file, without trusting
any field the ingest pipeline might drop.
"""

import re
import struct
from datetime import datetime
from pathlib import Path

from app.config import get_settings
from app.models.session import ReplayFrame, SessionReplay
from app.services import session_builder

# Cowrie's `TTYSTRUCT` (cowrie/core/ttylog.py): op, tty, length, direction, sec, usec.
_HEADER = struct.Struct("<iLiiLL")
_OP_OPEN, _OP_WRITE = 1, 3
_OUTPUT, _INTERACT = 2, 3  # input keystrokes (1) are echoed in the output already
_SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_BYTES = 5_000_000  # per recording; a longer one plays truncated
# A recording opened this long before the session started, or after it ended,
# belongs to another session.
_SHARED_SLACK_S = 5.0


def parse_ttylog(raw: bytes) -> tuple[float | None, list[tuple[float, str]]]:
    """(open time, [(time, text)]) from one Cowrie TTY log. Pure.

    Times are epoch seconds. Exec-channel commands (TYPE_INTERACT) are shown
    as a `$ ` line, since nothing echoes them. A torn final record is dropped.
    """
    opened: float | None = None
    frames: list[tuple[float, str]] = []
    offset = 0
    while offset + _HEADER.size <= len(raw):
        op, _tty, length, direction, sec, usec = _HEADER.unpack_from(raw, offset)
        offset += _HEADER.size
        data = raw[offset : offset + length]
        if len(data) < length:
            break
        offset += length
        stamp = sec + usec / 1_000_000
        if op == _OP_OPEN and opened is None:
            opened = stamp
        elif op == _OP_WRITE and direction in (_OUTPUT, _INTERACT):
            text = data.decode("utf-8", errors="replace")
            frames.append((stamp, f"$ {text}\r\n" if direction == _INTERACT else text))
    return opened, frames


def _epoch(timestamp: str) -> float:
    return datetime.fromisoformat(timestamp).timestamp()


async def build_replay(session_id: str) -> SessionReplay:
    settings = get_settings()
    if not settings.cowrie_tty_path and not settings.tty_paths:
        return SessionReplay(status="not_configured")

    events = await session_builder.get_session_events(session_id)
    honeypot = events[0].honeypot.id if events else None
    tty_path = settings.tty_paths.get(honeypot) or settings.cowrie_tty_path
    if not tty_path:
        return SessionReplay(status="not_configured")
    hashes = [
        e.file.hash.sha256
        for e in events
        if e.event.action == "cowrie.log.closed" and e.file and e.file.hash and e.file.hash.sha256
    ]
    # The hash becomes a file name: anything but 64 hex characters is refused
    # rather than joined onto a path.
    hashes = [h for h in hashes if _SHA256.fullmatch(h)]
    if not hashes:
        return SessionReplay(status="no_recording")

    start, end = _epoch(events[0].timestamp), _epoch(events[-1].timestamp)
    frames: list[tuple[float, str]] = []
    first_open: float | None = None
    shared = truncated = False
    for sha in dict.fromkeys(hashes):
        path = Path(tty_path) / sha
        if not path.is_file():
            continue
        with path.open("rb") as f:
            raw = f.read(MAX_BYTES + 1)
        truncated |= len(raw) > MAX_BYTES
        opened, recorded = parse_ttylog(raw[:MAX_BYTES])
        if opened is not None:
            shared |= not (start - _SHARED_SLACK_S <= opened <= end + _SHARED_SLACK_S)
            first_open = opened if first_open is None else min(first_open, opened)
        frames.extend(recorded)

    if first_open is None and not frames:
        return SessionReplay(status="missing")
    frames.sort(key=lambda f: f[0])
    zero = first_open if first_open is not None else frames[0][0]
    out = [ReplayFrame(t=round(max(0.0, t - zero), 3), data=d) for t, d in frames]
    return SessionReplay(
        status="ok",
        frames=out,
        duration=out[-1].t if out else 0,
        shared=shared,
        truncated=truncated,
    )
