"""infra/wild-vm/guard.sh, the live honeypot's retention, disk floor and egress
budget -- the real script, driven with stub docker/df/logger on PATH."""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parents[2] / "infra" / "wild-vm" / "guard.sh"
SH = shutil.which("sh")
pytestmark = pytest.mark.skipif(SH is None, reason="needs a POSIX sh")

STUBS = {
    "docker": """#!/bin/sh
echo "$*" >>"$CALLS"
case "$1 $2" in
  "volume inspect") echo "$LOGS" ;;
  "inspect -f") echo "$RUNNING" ;;
esac
""",
    "df": """#!/bin/sh
printf 'Avail\\n%s\\n' "$FREE_KB"
""",
    "logger": """#!/bin/sh
shift 2
echo "$*" >>"$SAID"
""",
}


def guard(
    tmp: Path, *, tx: int, running: bool = True, free_kb: int = 5_000_000, budget: int = 1000
):
    stubs = tmp / "bin"
    if not stubs.exists():
        stubs.mkdir()
        for name, body in STUBS.items():
            (stubs / name).write_text(body, newline="\n")
            (stubs / name).chmod(0o755)
        (tmp / "logs").mkdir()
    (tmp / "tx").write_text(str(tx))
    calls = tmp / "calls"
    calls.write_text("")
    env = {
        **os.environ,
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "CALLS": str(calls),
        "SAID": str(tmp / "said"),
        "LOGS": str(tmp / "logs"),
        "RUNNING": "true" if running else "false",
        "FREE_KB": str(free_kb),
        "EGRESS_BUDGET": str(budget),
        "TX": str(tmp / "tx"),
        "STATE": str(tmp / "state"),
    }
    subprocess.run([SH, str(GUARD)], env=env, check=True)
    return [c for c in calls.read_text().splitlines() if c.split()[0] in ("stop", "start")]


def egress(tmp: Path) -> int:
    (month_file,) = (tmp / "state").glob("egress-*")
    return int(month_file.read_text())


def test_egress_is_summed_across_a_reboot(tmp_path: Path) -> None:
    assert guard(tmp_path, tx=500, budget=10_000) == []
    assert egress(tmp_path) == 500  # first run: everything since boot
    guard(tmp_path, tx=700, budget=10_000)
    assert egress(tmp_path) == 700
    guard(tmp_path, tx=100, budget=10_000)  # counter went down: rebooted
    assert egress(tmp_path) == 800


def test_over_budget_stops_cowrie_and_lifts_the_stop_only_when_back_under(tmp_path: Path) -> None:
    assert guard(tmp_path, tx=2000, budget=1000) == ["stop cowrie"]
    assert "egress" in (tmp_path / "state" / "stopped").read_text()
    assert guard(tmp_path, tx=2000, running=False, budget=1000) == []  # still over
    assert guard(tmp_path, tx=2000, running=False, budget=10_000) == ["start cowrie"]
    assert not (tmp_path / "state" / "stopped").exists()


def test_a_cowrie_stopped_by_hand_is_left_alone(tmp_path: Path) -> None:
    assert guard(tmp_path, tx=10, running=False) == []


def test_the_disk_floor_stops_cowrie(tmp_path: Path) -> None:
    assert guard(tmp_path, tx=10, free_kb=1000) == ["stop cowrie"]
    assert "disk" in (tmp_path / "state" / "stopped").read_text()


def test_retention_deletes_only_old_rotated_logs(tmp_path: Path) -> None:
    guard(tmp_path, tx=10)  # creates the stub logs volume
    logs, old = tmp_path / "logs", time.time() - 100 * 86400
    for name in ("cowrie.json", "cowrie.json.2026-01-01", "cowrie.json.2026-10-17"):
        (logs / name).write_text("{}\n")
    os.utime(logs / "cowrie.json", (old, old))
    os.utime(logs / "cowrie.json.2026-01-01", (old, old))
    guard(tmp_path, tx=10)
    assert sorted(p.name for p in logs.iterdir()) == ["cowrie.json", "cowrie.json.2026-10-17"]
