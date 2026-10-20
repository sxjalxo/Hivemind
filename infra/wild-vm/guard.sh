#!/bin/sh
# Hivemind live honeypot guard, run every 5 minutes by /etc/cron.d/hivemind-guard.
#
# Three bounds on a box that faces the internet with a 10 GB disk and metered
# outbound traffic (GCP free tier: 1 GB/month from North America, billing
# months in Pacific time):
#   1. Retention: rotated cowrie.json files and TTY recordings older than
#      KEEP_DAYS are deleted; wild-pull copied both home long before. Downloads
#      are NOT copied home, so they are never aged out here; the disk floor
#      bounds them.
#   2. Disk floor: with less than DISK_FLOOR_KB free, Cowrie is stopped, so file
#      after file uploaded by an attacker cannot fill the disk sshd and the OS need.
#   3. Egress budget: once this billing month's outbound bytes pass
#      EGRESS_BUDGET, Cowrie is stopped until the month turns. Counted on the
#      interface, so unbilled metadata-server and firewall-dropped packets are
#      included: it errs toward stopping early.
# Every action is logged (journalctl -t hivemind-guard). A stop is lifted only
# by this script, only once no bound is exceeded; a Cowrie stopped by hand is
# left alone. This month's count: cat /var/lib/hivemind/egress-YYYY-MM
set -eu
# Overridable only so backend/tests/test_wild_guard.py can drive it.
EGRESS_BUDGET=${EGRESS_BUDGET:-900000000} # bytes; 10% under the free 1 GB
DISK_FLOOR_KB=${DISK_FLOOR_KB:-1048576}
KEEP_DAYS=90 # ponytail: by age, not by "pulled"; wild-pull down for 90 days loses the oldest day
TX=${TX:-/sys/class/net/ens4/statistics/tx_bytes}
STATE=${STATE:-/var/lib/hivemind}
mkdir -p "$STATE"
say() { logger -t hivemind-guard "$*"; }

# 1. Retention.
logs=$(docker volume inspect -f '{{.Mountpoint}}' cowrie-logs)
# Tolerant: a missing recordings volume must not end the run before the egress check.
tty=$(docker volume inspect -f '{{.Mountpoint}}' cowrie-tty 2>/dev/null || true)
{
  find "$logs" -maxdepth 1 -name 'cowrie.json.*' -mtime +"$KEEP_DAYS" -print -delete
  [ -z "$tty" ] || find "$tty" -maxdepth 1 -type f -mtime +"$KEEP_DAYS" -print -delete
} | while read -r gone; do say "retention: deleted $gone"; done

# 2. Free disk.
free_kb=$(df --output=avail -k / | tail -1 | tr -d ' ')

# 3. This billing month's egress. The counter restarts at boot: a reading below
#    the last one means a reboot, so all of it is new. On the first run ever,
#    the bytes since boot are counted (an overestimate when booted last month).
month=$(TZ=America/Los_Angeles date +%Y-%m)
raw=$(cat "$TX")
last=$(cat "$STATE/tx-last" 2>/dev/null || echo 0)
if [ "$raw" -ge "$last" ]; then delta=$((raw - last)); else delta=$raw; fi
total=$(($(cat "$STATE/egress-$month" 2>/dev/null || echo 0) + delta))
echo "$total" >"$STATE/egress-$month"
echo "$raw" >"$STATE/tx-last"

reason=""
if [ "$free_kb" -lt "$DISK_FLOOR_KB" ]; then reason="disk: ${free_kb} KB free"; fi
if [ "$total" -gt "$EGRESS_BUDGET" ]; then
  reason="${reason:+$reason; }egress: $total bytes sent in $month"
fi

if [ -n "$reason" ]; then
  if [ "$(docker inspect -f '{{.State.Running}}' cowrie)" = true ]; then
    docker stop cowrie >/dev/null
    echo "$reason" >"$STATE/stopped"
    say "stopped cowrie: $reason"
  fi
elif [ -f "$STATE/stopped" ]; then
  docker start cowrie >/dev/null
  rm "$STATE/stopped"
  say "started cowrie: no bound exceeded"
fi
