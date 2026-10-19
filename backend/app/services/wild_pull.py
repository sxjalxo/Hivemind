"""Read a remote Cowrie's log over SSH. Two remotes speak this, both on the GCP VM:

* **The live honeypot** (`Remote`), copied home with the admin key by the
  `wild-pull` service (scripts/pull_wild.py) every five minutes, into a file
  Filebeat ships.
* **The evaluation honeypot** (`Gate`), a second Cowrie only the owner's IP can
  reach. Its key is tied by a forced command to infra/wild-vm/eval-gate.sh,
  which can list and read that Cowrie's log and clear its residue -- nothing
  else on the VM. An evaluation run resets through it before starting and
  indexes its log directly before reading its own session back
  (`app.services.evaluation.remote_log`).

Two things make the live pull safe to repeat:

* **No line is read twice.** The position is (inode, byte offset) of the
  remote file, saved after every pull. Cowrie rotates daily by RENAMING
  `cowrie.json` to `cowrie.json.YYYY-MM-DD` -- the inode moves with the name --
  so a rotation is seen as "my inode now has a dated name": that file is
  finished from the saved offset, then the new `cowrie.json` starts at 0. Only
  whole lines are taken; a half-written last line waits for the next pull.
  Two pullers on one directory would both start from the same offset, so
  `locked` keeps it to one.
* **It talks only to the right machine.** The VM's SSH host key is pinned; a
  different key is refused, never learned.
"""

import base64
import contextlib
import json
import logging
import os
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import paramiko

from app.config import EvalGate

log = logging.getLogger("wild_pull")

LIVE = "cowrie.json"
# Names come from the remote listing and are put into a command, so only
# exactly these two shapes are ever accepted.
_NAME = re.compile(r"^cowrie\.json(?:\.\d{4}-\d{2}-\d{2})?$")
MAX_CHUNK = 20 * 1024 * 1024  # per file per pull; the rest comes next time
# Cowrie names a finished TTY recording by the SHA-256 of its input; nothing else
# in that volume is a finished recording, and the name is put into a command.
_TTY = re.compile(r"^[0-9a-f]{64}$")
MAX_TTY_BYTES = 5_000_000  # the replay reads no more than this (app.services.replay)


@dataclass(frozen=True)
class RemoteFile:
    inode: int
    size: int
    name: str


@dataclass(frozen=True)
class Read:
    name: str
    start: int
    end: int  # exclusive; may shrink to the last whole line once read


@dataclass(frozen=True)
class Position:
    inode: int
    offset: int


def plan(position: Position | None, files: list[RemoteFile]) -> tuple[list[Read], str | None]:
    """What to read this pull, and a warning if continuity was lost. Pure.

    Returns reads in order: the rest of a rotated file first, then the live one.
    """
    live = next((f for f in files if f.name == LIVE), None)
    by_inode = {f.inode: f for f in files}
    reads: list[Read] = []
    warning = None

    if position is None:
        if any(f.name != LIVE for f in files):
            warning = "first pull: rotated files already on the VM are not backfilled"
        return ([Read(LIVE, 0, live.size)] if live else []), warning

    mine = by_inode.get(position.inode)
    if mine is None:
        warning = f"inode {position.inode} is gone from the VM; resuming at the live log's start"
        return ([Read(LIVE, 0, live.size)] if live else []), warning
    if mine.size < position.offset:
        warning = f"{mine.name} shrank below the saved offset; re-reading it from 0"
        return [Read(mine.name, 0, mine.size)], warning
    if mine.name != LIVE:  # rotated since the last pull: finish it, then start the new one
        reads.append(Read(mine.name, position.offset, mine.size))
        if live and live.inode != mine.inode:
            reads.append(Read(LIVE, 0, live.size))
        return reads, warning
    return [Read(LIVE, position.offset, mine.size)], warning


def whole_lines(chunk: bytes) -> bytes:
    """The chunk up to and including its last newline. Pure."""
    cut = chunk.rfind(b"\n")
    return chunk[: cut + 1] if cut >= 0 else b""


def parse_listing(out: bytes) -> list[RemoteFile]:
    """`stat -c '%i %s %n'` lines, keeping only the two accepted names."""
    files = []
    for line in out.decode().splitlines():
        inode, size, name = line.split(" ", 2)
        if _NAME.fullmatch(name):
            files.append(RemoteFile(int(inode), int(size), name))
    return files


def _checked(name: str) -> str:
    if not _NAME.fullmatch(name):
        raise ValueError(f"refusing remote name {name!r}")
    return name


class _Ssh:
    def __init__(self, host: str, port: int, user: str, key_file: str, host_key: str):
        kind, blob = host_key.split()[:2]
        pinned = paramiko.PKey.from_type_string(kind, base64.b64decode(blob))
        self.client = paramiko.SSHClient()
        self.client.get_host_keys().add(f"[{host}]:{port}" if port != 22 else host, kind, pinned)
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.client.connect(
            host,
            port=port,
            username=user,
            key_filename=key_file,
            look_for_keys=False,
            allow_agent=False,
            timeout=30,
            compress=True,  # the VM's egress is metered (1 GB/month free); JSON shrinks ~10x
        )

    def _exec(self, command: str) -> bytes:
        _, stdout, stderr = self.client.exec_command(command)
        out = stdout.read()
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError(f"remote command failed: {stderr.read().decode(errors='replace')}")
        return out

    def close(self) -> None:
        self.client.close()


def _mountpoint(volume: str) -> str:
    return f'"$(docker volume inspect -f {{{{.Mountpoint}}}} {shlex.quote(volume)})"'


class Remote(_Ssh):
    """The live honeypot's log and recording volumes, read with the admin key and sudo."""

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        key_file: str,
        host_key: str,
        volume: str,
        tty_volume: str = "cowrie-tty",
    ):
        super().__init__(host, port, user, key_file, host_key)
        self.dir = _mountpoint(volume)
        self.tty_dir = _mountpoint(tty_volume)

    def _run(self, command: str) -> bytes:
        return self._exec(f"sudo sh -c {shlex.quote(command)}")

    def listing(self) -> list[RemoteFile]:
        return parse_listing(
            self._run(f"cd {self.dir} && stat -c '%i %s %n' cowrie.json* 2>/dev/null || true")
        )

    def read(self, name: str, start: int, length: int) -> bytes:
        return self._run(
            f"cd {self.dir} && tail -c +{start + 1} {_checked(name)} | head -c {length}"
        )

    def tty_names(self) -> list[str]:
        out = self._run(f"cd {self.tty_dir} && ls -1")
        return [name for name in out.decode().split() if _TTY.fullmatch(name)]

    def read_tty(self, name: str) -> bytes:
        if not _TTY.fullmatch(name):
            raise ValueError(f"refusing recording name {name!r}")
        return self._run(f"cd {self.tty_dir} && head -c {MAX_TTY_BYTES} {name}")


class Gate(_Ssh):
    """The evaluation honeypot, through infra/wild-vm/eval-gate.sh.

    The key is pinned to that script by a forced command, so what is sent here
    is not run: the gate reads it as SSH_ORIGINAL_COMMAND and accepts only
    these three verbs.
    """

    def listing(self) -> list[RemoteFile]:
        return parse_listing(self._exec("list"))

    def read(self, name: str, start: int, length: int) -> bytes:
        return self._exec(f"read {_checked(name)} {int(start)} {int(length)}")

    def reset(self) -> None:
        self._exec("reset")


def _load(state_file: Path) -> Position | None:
    if not state_file.exists():
        return None
    raw = json.loads(state_file.read_text())
    return Position(raw["inode"], raw["offset"])


def _save(state_file: Path, position: Position) -> None:
    tmp = state_file.with_suffix(".tmp")
    tmp.write_text(json.dumps({"inode": position.inode, "offset": position.offset}))
    os.replace(tmp, state_file)


class PullerBusy(RuntimeError):
    """Another puller holds this directory."""


@contextlib.contextmanager
def locked(out_dir: Path) -> Iterator[None]:
    """Hold `out_dir` against a second puller.

    Two pullers on one directory both read from the same saved offset and
    append the same lines twice (2026-10-18: a --once beside the service did).
    """
    import fcntl  # Linux, like the containers that pull; absent on a Windows dev host

    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / ".lock").open("w") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PullerBusy(f"another puller holds {out_dir}") from None
        yield


def pull_once(remote: Remote, out_dir: Path) -> int:
    """One pull. Returns the number of bytes appended locally."""
    out_dir.mkdir(parents=True, exist_ok=True)
    state_file, target = out_dir / "position.json", out_dir / "cowrie.json"
    files = remote.listing()
    by_name = {f.name: f for f in files}
    reads, warning = plan(_load(state_file), files)
    if warning:
        log.warning(warning)

    appended = 0
    for read in reads:
        length = min(read.end - read.start, MAX_CHUNK)
        if length <= 0:
            if read.name == LIVE:
                _save(state_file, Position(by_name[LIVE].inode, read.start))
            continue
        data = whole_lines(remote.read(read.name, read.start, length))
        if data:
            # ponytail: a crash between this append and the state save below
            # re-appends this chunk next time (duplicate events). The window is
            # one fsync wide; a journal would close it if it ever matters.
            with target.open("ab") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            appended += len(data)
        _save(state_file, Position(by_name[read.name].inode, read.start + len(data)))
        if read.start + len(data) < read.end:
            break  # chunk cap or half-written line: finish this file before the next
    return appended


def sync_tty(remote: Remote, out_dir: Path) -> int:
    """Copy the finished TTY recordings that are not here yet. Returns how many.

    No offsets: Cowrie renames a recording to the SHA-256 of its input only when
    its channel closes, and never writes to it again (a session that types the
    same input reuses the existing file). A name that exists here is therefore
    complete, and a copy is written to a temporary name first so an interrupted
    one is never mistaken for a finished one.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for name in remote.tty_names():
        target = out_dir / name
        if target.exists():
            continue
        tmp = out_dir / f".{name}.part"
        tmp.write_bytes(remote.read_tty(name))
        os.replace(tmp, target)
        copied += 1
    return copied


def _open_gate(cfg: EvalGate) -> Gate:
    key = os.path.expanduser(cfg.key_file)
    return Gate(cfg.host, cfg.port, cfg.user, key, cfg.host_key)


def reset_through_gate(cfg: EvalGate) -> None:
    """Clear the evaluation Cowrie's residue; raises unless the gate confirmed it."""
    gate = _open_gate(cfg)
    try:
        gate.reset()
    finally:
        gate.close()


def read_live_log(cfg: EvalGate) -> tuple[int, bytes]:
    """The evaluation Cowrie's whole current log, as (inode, whole lines).

    ponytail: all of today's file on every call, and never a rotated one. It
    holds only our own runs, so it stays small; a run that straddles Cowrie's
    midnight rotation loses its chain events to the rotated file and reports
    them TIMEOUT. Keep a position the way `pull_once` does if that ever bites.
    """
    gate = _open_gate(cfg)
    try:
        live = next((f for f in gate.listing() if f.name == LIVE), None)
        if live is None:
            return 0, b""
        return live.inode, whole_lines(gate.read(LIVE, 0, min(live.size, MAX_CHUNK)))
    finally:
        gate.close()
