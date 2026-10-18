"""Pull the live honeypot's Cowrie log home, for Filebeat to ship (honeypot.id gcp-wild-01).

    docker compose --profile wild up -d wild-pull        # every 5 min, as a service
    python -m scripts.pull_wild --once                   # one pull, from backend/
    (a --once beside the running service is refused: they share one position file)

The VM keeps its own log and accepts no inbound traffic but the owner's admin
SSH, so the logs are PULLED: this connects to that sshd, reads only the bytes
appended since the last pull, and appends them to one local file that never
rotates. Filebeat follows that file like any other honeypot's log.

Two things make it safe to run on a timer:

* **No event is read twice.** The position is (inode, byte offset) of the
  remote file, saved after every pull. Cowrie rotates daily by RENAMING
  `cowrie.json` to `cowrie.json.YYYY-MM-DD` -- the inode moves with the name --
  so a rotation is seen as "my inode now has a dated name": that file is
  finished from the saved offset, then the new `cowrie.json` starts at 0. Only
  whole lines are taken; a half-written last line waits for the next pull.
* **It talks only to the right machine.** The VM's SSH host key is pinned
  (`WILD_HOST_KEY`); a different key is refused, never learned.

Configuration is environment only (see the `wild-pull` service in
docker-compose.yml); nothing about the VM is hard-coded.
"""

import argparse
import base64
import json
import logging
import os
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

log = logging.getLogger("pull_wild")

LIVE = "cowrie.json"
# Names come from the remote listing and are put into a shell command, so only
# exactly these two shapes are ever accepted.
_NAME = re.compile(r"^cowrie\.json(?:\.\d{4}-\d{2}-\d{2})?$")
MAX_CHUNK = 20 * 1024 * 1024  # per file per pull; the rest comes next time


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


class Remote:
    def __init__(self, host: str, port: int, user: str, key_file: str, host_key: str, volume: str):
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
        self.dir = f'"$(docker volume inspect -f {{{{.Mountpoint}}}} {shlex.quote(volume)})"'

    def _run(self, command: str) -> bytes:
        _, stdout, stderr = self.client.exec_command(f"sudo sh -c {shlex.quote(command)}")
        out = stdout.read()
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError(f"remote command failed: {stderr.read().decode(errors='replace')}")
        return out

    def listing(self) -> list[RemoteFile]:
        out = self._run(f"cd {self.dir} && stat -c '%i %s %n' cowrie.json* 2>/dev/null || true")
        files = []
        for line in out.decode().splitlines():
            inode, size, name = line.split(" ", 2)
            if _NAME.fullmatch(name):
                files.append(RemoteFile(int(inode), int(size), name))
        return files

    def read(self, name: str, start: int, length: int) -> bytes:
        if not _NAME.fullmatch(name):
            raise ValueError(f"refusing remote name {name!r}")
        return self._run(f"cd {self.dir} && tail -c +{start + 1} {name} | head -c {length}")

    def close(self) -> None:
        self.client.close()


def _load(state_file: Path) -> Position | None:
    if not state_file.exists():
        return None
    raw = json.loads(state_file.read_text())
    return Position(raw["inode"], raw["offset"])


def _save(state_file: Path, position: Position) -> None:
    tmp = state_file.with_suffix(".tmp")
    tmp.write_text(json.dumps({"inode": position.inode, "offset": position.offset}))
    os.replace(tmp, state_file)


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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="pull once and exit")
    parser.add_argument("--every", type=int, default=300, metavar="SECONDS")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    env = os.environ
    config = dict(
        host=env["WILD_HOST"],
        port=int(env.get("WILD_PORT", "50022")),
        user=env["WILD_USER"],
        key_file=env.get("WILD_KEY_FILE", "/run/secrets/wild_key"),
        host_key=env["WILD_HOST_KEY"],
        volume=env.get("WILD_VOLUME", "cowrie-logs"),
    )
    out_dir = Path(env.get("WILD_OUT_DIR", "/wild-logs/gcp-wild-01"))
    # Two pullers on one directory both read from the same saved offset and
    # append the same lines twice (2026-10-18: a --once beside the service did).
    import fcntl  # Linux-only, like the container; tests drive pull_once directly

    out_dir.mkdir(parents=True, exist_ok=True)
    lock = (out_dir / ".lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit(f"another wild-pull holds {out_dir}; stop it first") from None
    while True:
        try:
            remote = Remote(**config)
            try:
                log.info("pulled %d bytes", pull_once(remote, out_dir))
            finally:
                remote.close()
        except Exception:  # a timer must survive one bad pull (VM stopped, IP changed)
            if args.once:
                raise
            log.exception("pull failed; retrying in %ds", args.every)
        if args.once:
            return
        time.sleep(args.every)


if __name__ == "__main__":
    main()
