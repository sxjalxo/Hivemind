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
  "volume inspect") case "$*" in *cowrie-tty) [ -n "$TTY" ] || exit 1; echo "$TTY" ;; *) echo "$LOGS" ;; esac ;;
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
    # -C answers from IPT_PRESENT (0 = rule exists; the mangle egress chain from
    # IPT_EGRESS_PRESENT); -L prints a counter fixture per chain;
    # IPT_FAIL=1 makes every call fail, as a missing module or a locked xtables would.
    "iptables": """#!/bin/sh
echo "$*" >>"$IPT_CALLS"
[ "$IPT_FAIL" = 1 ] && exit 1
table=filter
[ "$1" = -t ] && { table=$2; shift 2; }
case "$table $1" in
  "mangle -C") case "$*" in *ctorigdstport*) exit "$IPT_PORTS_PRESENT" ;; *) exit "$IPT_EGRESS_PRESENT" ;; esac ;;
  "mangle -L") printf 'Chain HIVEMIND-EGRESS (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      10      600 RETURN     all  --  *      *       0.0.0.0/0            35.235.240.0/20
       1       60 RETURN     all  --  *      *       0.0.0.0/0            169.254.169.254
      40     2000            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            ctorigdstport 22
     200    90000            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            ctorigdstport 23
     300   123456 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0
' ;;
  "filter -C") exit "$IPT_PRESENT" ;;
  "filter -L") printf 'Chain DOCKER-USER
 pkts bytes target
   40  2400 DROP tcp
    2   120 DROP tcp
  900 50000 RETURN all
' ;;
esac
exit 0
""",
}


def guard(
    tmp: Path,
    *,
    tx: int,
    running: bool = True,
    free_kb: int = 5_000_000,
    budget: int = 1000,
    tty: bool = True,
    ipt_present: bool = True,
    ipt_fail: bool = False,
    rate_limit: str = "on",
    minute: str = "17",
    counter: str = "file",  # "iptables": the real path, the mangle chain's counter
    egress_chain_present: bool = True,
    port_counters_present: bool = True,
    iface_tx: int = 0,
):
    stubs = tmp / "bin"
    if not stubs.exists():
        stubs.mkdir()
        for name, body in STUBS.items():
            (stubs / name).write_text(body, newline="\n")
            (stubs / name).chmod(0o755)
        (tmp / "logs").mkdir()
        (tmp / "tty").mkdir()
    (tmp / "tx").write_text(str(tx))
    (tmp / "iface_tx").write_text(str(iface_tx))
    calls = tmp / "calls"
    calls.write_text("")
    env = {
        **os.environ,
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "CALLS": str(calls),
        "SAID": str(tmp / "said"),
        "LOGS": str(tmp / "logs"),
        "TTY": str(tmp / "tty") if tty else "",  # "" = no such volume: inspect fails
        "RUNNING": "true" if running else "false",
        "FREE_KB": str(free_kb),
        "EGRESS_BUDGET": str(budget),
        "TX": str(tmp / "tx") if counter == "file" else "",
        "IFACE_TX": str(tmp / "iface_tx"),
        "IPT_EGRESS_PRESENT": "0" if egress_chain_present else "1",
        "IPT_PORTS_PRESENT": "0" if port_counters_present else "1",
        "STATE": str(tmp / "state"),
        "IPT_CALLS": str(tmp / "ipt"),
        "IPT_PRESENT": "0" if ipt_present else "1",
        "IPT_FAIL": "1" if ipt_fail else "0",
        "RATE_LIMIT": rate_limit,
        "NOW_MINUTE": minute,
    }
    (tmp / "ipt").write_text("")
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


def test_retention_deletes_only_old_recordings(tmp_path: Path) -> None:
    guard(tmp_path, tx=10)  # creates the stub tty volume
    tty, old = tmp_path / "tty", time.time() - 100 * 86400
    for name in ("a" * 64, "b" * 64):
        (tty / name).write_bytes(b"rec")
    os.utime(tty / ("a" * 64), (old, old))
    guard(tmp_path, tx=10)
    assert [p.name for p in tty.iterdir()] == ["b" * 64]
    assert "retention: deleted" in (tmp_path / "said").read_text()


def test_a_missing_recordings_volume_still_reaches_the_egress_check(tmp_path: Path) -> None:
    assert guard(tmp_path, tx=5000, budget=1000, tty=False) == ["stop cowrie"]


def ipt(tmp: Path, verb: str) -> list[str]:
    return [c for c in (tmp / "ipt").read_text().splitlines() if c.startswith(verb)]


def test_missing_rate_limit_rules_are_installed_once_each(tmp_path: Path) -> None:
    guard(tmp_path, tx=10, ipt_present=False)
    inserted = ipt(tmp_path, "-I")
    assert len(inserted) == 4  # ssh + telnet, each a rate and a concurrency rule
    ssh = [r for r in inserted if "--ctorigdstport 22 " in r]
    telnet = [r for r in inserted if "--ctorigdstport 23 " in r]
    assert len(ssh) == len(telnet) == 2
    assert any("--hashlimit-above 2/minute --hashlimit-burst 6" in r for r in ssh)
    assert any("--connlimit-above 3 --connlimit-mask 24" in r for r in ssh)
    # Telnet: one new connection per 10 minutes and one at a time, per /24.
    assert any("--hashlimit-name telnet-strict" in r for r in telnet)
    assert any("--hashlimit-above 6/hour --hashlimit-burst 2" in r for r in telnet)
    assert any("--connlimit-above 1 --connlimit-mask 24" in r for r in telnet)
    assert all(r.startswith("-I DOCKER-USER ") and r.endswith("-j DROP") for r in inserted)
    assert all("--hashlimit-srcmask 24" in r for r in inserted if "hashlimit" in r)
    # Never the evaluation Cowrie: every IAP connection reaches it from a few proxy
    # addresses, so a per-source limit there would throttle our own evaluations.
    assert not any("2222" in r or "2223" in r for r in inserted)
    assert (tmp_path / "state" / "rate-limit-since").read_text().strip()
    assert "rate limit: installed" in (tmp_path / "said").read_text()


def test_present_rules_are_left_alone(tmp_path: Path) -> None:
    guard(tmp_path, tx=10, ipt_present=True)
    assert ipt(tmp_path, "-I") == []
    assert len(ipt(tmp_path, "-C")) == 4


def test_a_failing_iptables_never_skips_the_egress_bound(tmp_path: Path) -> None:
    assert guard(tmp_path, tx=5000, budget=1000, ipt_fail=True) == ["stop cowrie"]
    assert egress(tmp_path) == 5000
    assert "rate limit:" in (tmp_path / "said").read_text()


def test_the_rate_limit_can_be_switched_off(tmp_path: Path) -> None:
    guard(tmp_path, tx=10, ipt_present=False, rate_limit="off")
    assert (tmp_path / "ipt").read_text() == ""


def test_the_hourly_run_logs_how_many_connections_were_turned_away(tmp_path: Path) -> None:
    guard(tmp_path, tx=10, minute="00")
    assert "rate limit: 42 new connections dropped" in (tmp_path / "said").read_text()
    guard(tmp_path, tx=10, minute="35")  # not on the hour: nothing more said
    assert (tmp_path / "said").read_text().count("connections dropped") == 1


def test_internet_bound_bytes_come_from_the_egress_chain(tmp_path: Path) -> None:
    # The chain's catch-all rule: what is left after IAP and the metadata server.
    assert guard(tmp_path, tx=0, counter="iptables", budget=10**9) == []
    assert egress(tmp_path) == 123456
    assert ipt(tmp_path, "-t mangle -A") == []  # already installed: left alone


def test_a_missing_egress_chain_is_installed_excluding_iap_and_metadata(tmp_path: Path) -> None:
    guard(tmp_path, tx=0, counter="iptables", egress_chain_present=False, budget=10**9)
    assert ipt(tmp_path, "-t mangle -A") == [
        "-t mangle -A HIVEMIND-EGRESS -d 35.235.240.0/20 -j RETURN",
        "-t mangle -A HIVEMIND-EGRESS -d 169.254.169.254/32 -j RETURN",
        "-t mangle -A HIVEMIND-EGRESS -j RETURN",
        "-t mangle -A POSTROUTING -o ens4 -j HIVEMIND-EGRESS",
    ]
    assert "counting internet-bound bytes" in (tmp_path / "said").read_text()


def test_a_failing_iptables_falls_back_to_the_interface_total(tmp_path: Path) -> None:
    assert guard(
        tmp_path, tx=0, counter="iptables", ipt_fail=True, iface_tx=5000, budget=1000
    ) == ["stop cowrie"]
    assert egress(tmp_path) == 5000
    assert "counting the interface total" in (tmp_path / "said").read_text()


def test_the_old_telnet_rules_are_retired_on_every_run(tmp_path: Path) -> None:
    guard(tmp_path, tx=10)
    deleted = ipt(tmp_path, "-D")
    assert len(deleted) == 2
    assert all("--ctorigdstport 23 " in r for r in deleted)
    assert any("--hashlimit-name cowrie-23 " in r and "2/minute" in r for r in deleted)
    assert any("--connlimit-above 3 " in r for r in deleted)


def test_missing_per_port_counters_are_added_ahead_of_the_catch_all(tmp_path: Path) -> None:
    guard(tmp_path, tx=0, counter="iptables", port_counters_present=False, budget=10**9)
    assert ipt(tmp_path, "-t mangle -I") == [
        "-t mangle -I HIVEMIND-EGRESS 3 -p tcp -m conntrack --ctorigdstport 22",
        "-t mangle -I HIVEMIND-EGRESS 3 -p tcp -m conntrack --ctorigdstport 23",
    ]
    assert egress(tmp_path) == 123456  # still the catch-all, not a port rule


def test_the_hourly_run_logs_bytes_per_port(tmp_path: Path) -> None:
    guard(tmp_path, tx=0, counter="iptables", budget=10**9, minute="00")
    said = (tmp_path / "said").read_text()
    assert "egress: port 22 2000 bytes, port 23 90000 bytes since the chain was installed" in said


def test_a_months_budget_can_be_raised_by_hand_but_never_by_a_bad_file(tmp_path: Path) -> None:
    guard(tmp_path, tx=10, budget=10**9)  # creates the state directory
    (month,) = [p.name.removeprefix("egress-") for p in (tmp_path / "state").glob("egress-*")]
    budget_file = tmp_path / "state" / f"budget-{month}"
    budget_file.write_text("5000")
    assert guard(tmp_path, tx=3000, budget=1000) == []  # 3000 counted, 5000 allowed
    budget_file.write_text("lots")
    assert guard(tmp_path, tx=3000, budget=1000) == ["stop cowrie"]  # falls back to 1000
