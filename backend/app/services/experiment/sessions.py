"""Per-session facts and per-block metrics for the persona experiment (R3). Pure.

The unit is a logged-in session; a block's value for a metric is computed over
its logged-in sessions, either one vote per session or one vote per script (the
ordered command sequence, as campaigns fingerprint it), so a botnet replaying
one script thousands of times cannot carry a block on its own.
"""

import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from functools import cache

from app.services.campaigns import fingerprint
from app.services.compaction import CompactedCommand
from app.services.mitre import rules

LOGIN = "cowrie.login.success"
COMMAND = "cowrie.command.input"
DOWNLOADS = ("cowrie.session.file_download", "cowrie.session.file_download.failed")
ACTIONS = ("cowrie.session.connect", LOGIN, COMMAND, *DOWNLOADS, "cowrie.session.closed")
# Fixed before any data was seen (spec section 4); never add to or reorder.
PRIMARY = ("ran_any_share", "commands_mean", "download_share")

_ARCH_TOKENS = {
    "arm": (
        "arm",
        "arm4",
        "arm5",
        "arm6",
        "arm7",
        "armv4l",
        "armv5l",
        "armv6l",
        "armv7l",
        "armhf",
        "armel",
        "aarch64",
        "arm64",
    ),
    "x86": ("x86", "x64", "amd64", "i386", "i486", "i586", "i686"),
    "mips": ("mips", "mipsel", "mpsl", "mips64"),
}
_TOKEN_ARCH = {token: arch for arch, tokens in _ARCH_TOKENS.items() for token in tokens}


@dataclass(frozen=True)
class Event:
    at: datetime
    action: str
    command: str | None = None
    url: str | None = None


@dataclass(frozen=True)
class SessionStats:
    session_id: str
    first: datetime
    last: datetime
    logged_in: bool
    commands: tuple[str, ...]
    download_archs: tuple[str, ...]  # one per download attempt

    @property
    def downloads(self) -> int:
        return len(self.download_archs)

    @property
    def duration_s(self) -> float:
        return (self.last - self.first).total_seconds()

    @property
    def script(self) -> str | None:
        return fingerprint(list(self.commands)) if self.commands else None


@dataclass
class Tally:
    sessions: list[SessionStats]  # logged in and complete: the ones analysed
    cut: int = 0  # logged in, still running when the block ended (the switch cut them)
    not_logged_in: int = 0


def url_arch(url: str) -> str:
    """The architecture a download URL's last segment names: arm, x86, mips or none."""
    tail = url.lower().rsplit("/", 1)[-1]
    for token in re.split(r"[^a-z0-9]+", tail):
        if token in _TOKEN_ARCH:
            return _TOKEN_ARCH[token]
    return "none"


def summarize(session_id: str, events: list[Event]) -> SessionStats:
    """One session from its events, oldest first."""
    return SessionStats(
        session_id,
        events[0].at,
        events[-1].at,
        any(e.action == LOGIN for e in events),
        tuple(e.command for e in events if e.action == COMMAND and e.command),
        tuple(url_arch(e.url) if e.url else "none" for e in events if e.action in DOWNLOADS),
    )


@cache
def _command_techniques(command: str) -> frozenset[str]:
    hits, _ = rules.apply_rules([CompactedCommand(event_id="", timestamp="", command=command)])
    return frozenset(hit.rule.id for hit in hits)


def techniques(s: SessionStats) -> frozenset[str]:
    """Rulebook techniques over the session's commands."""
    return frozenset().union(*(_command_techniques(c) for c in s.commands))


def assign(sessions, spans: list[tuple[datetime, datetime]]) -> list[Tally]:
    """Sort sessions into the spans [start, end) that hold their first event.

    A logged-in session whose last event is at or after its span's end was cut by
    the switch and is only counted, as is one that never logged in. Sessions
    outside every span are dropped.
    """
    tallies = [Tally([]) for _ in spans]
    for s in sessions:
        for tally, (start, end) in zip(tallies, spans, strict=True):
            if start <= s.first < end:
                if not s.logged_in:
                    tally.not_logged_in += 1
                elif s.last >= end:
                    tally.cut += 1
                else:
                    tally.sessions.append(s)
                break
    return tallies


def _values(s: SessionStats) -> dict[str, float]:
    return {
        "ran_any_share": float(bool(s.commands)),
        "commands_mean": float(len(s.commands)),
        "download_share": float(s.downloads > 0),
        "duration_s": s.duration_s,
    }


def _summarise(rows: list[dict[str, float]]) -> dict[str, float]:
    out = {m: statistics.fmean(r[m] for r in rows) for m in PRIMARY}
    out["duration_median_s"] = statistics.median(r["duration_s"] for r in rows)
    return out


def metrics(sessions: list[SessionStats]) -> dict[str, float]:
    """One vote per session: the three primaries and the median session length."""
    return _summarise([_values(s) for s in sessions])


def script_metrics(sessions: list[SessionStats]) -> dict[str, float]:
    """One vote per script: each script's mean, then over scripts (no-command sessions: one group)."""
    groups: dict[str | None, list[dict[str, float]]] = defaultdict(list)
    for s in sessions:
        groups[s.script].append(_values(s))
    return _summarise(
        [{k: statistics.fmean(r[k] for r in rows) for k in rows[0]} for rows in groups.values()]
    )


def technique_mix(sessions: list[SessionStats]) -> dict[str, float]:
    """Share of sessions showing each technique."""
    counts = Counter(t for s in sessions for t in techniques(s))
    return {t: n / len(sessions) for t, n in sorted(counts.items())}


def arch_mix(sessions: list[SessionStats]) -> dict[str, float]:
    """Share of download attempts per architecture named in the URL."""
    counts = Counter(a for s in sessions for a in s.download_archs)
    total = sum(counts.values())
    return {a: n / total for a, n in sorted(counts.items())} if total else {}
