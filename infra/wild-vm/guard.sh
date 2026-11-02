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
#   3. Egress budget: once this billing month's internet-bound bytes pass
#      EGRESS_BUDGET, Cowrie is stopped until the month turns. Counted by an
#      iptables chain (mangle HIVEMIND-EGRESS) on everything leaving ens4 except
#      IAP (35.235.240.0/20: our pulls, admin SSH, evaluation) and the metadata
#      server, which Google bills as free. Counting the interface total instead
#      stopped Cowrie on 2026-10-29 at 0.9 GB counted while the bill showed ~0.6
#      GiB of internet egress since August. If iptables fails, the interface
#      total is counted again: it errs toward stopping early.
#   4. Rate limit (2026-10-25): a few bots ran 300k+ events a day each and
#      Cowrie's replies alone outran the free tier, so each source /24 may open
#      RATE_PER_MIN new connections a minute (burst RATE_BURST) and hold
#      CONCURRENT at once on the live honeypot's ports 22/23. Excess SYNs are
#      dropped. The rules sit in Docker's DOCKER-USER chain and match the
#      ORIGINAL destination port (Docker DNATs 22->2222 into the container);
#      the evaluation Cowrie (host 2222/2223) is never limited -- every IAP
#      connection reaches it from a few proxy addresses. Re-checked every run,
#      so they survive reboots. Off: RATE_LIMIT=off, then iptables -F DOCKER-USER.
# Every action is logged (journalctl -t hivemind-guard). A stop is lifted only
# by this script, only once no bound is exceeded; a Cowrie stopped by hand is
# left alone. This month's count: cat /var/lib/hivemind/egress-YYYY-MM
set -eu
# Overridable only so backend/tests/test_wild_guard.py can drive it.
EGRESS_BUDGET=${EGRESS_BUDGET:-900000000} # bytes; 10% under the free 1 GB
DISK_FLOOR_KB=${DISK_FLOOR_KB:-1048576}
KEEP_DAYS=90 # ponytail: by age, not by "pulled"; wild-pull down for 90 days loses the oldest day
TX=${TX:-} # a file to read the byte count from instead (tests)
IFACE_TX=${IFACE_TX:-/sys/class/net/ens4/statistics/tx_bytes}
RATE_LIMIT=${RATE_LIMIT:-on}
RATE_PER_MIN=2 # calibration knobs: tune after seeing the drop counts
RATE_BURST=6
CONCURRENT=3
SRC_MASK=24
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

# 3. This billing month's egress. A counter restarts at boot (and the chain when
#    reinstalled): a reading below the last one means a restart, so all of it is
#    new. On the first run ever, the bytes since boot are counted.
internet_bytes() {
  if ! iptables -t mangle -C POSTROUTING -o ens4 -j HIVEMIND-EGRESS 2>/dev/null; then
    iptables -t mangle -N HIVEMIND-EGRESS 2>/dev/null || true
    iptables -t mangle -F HIVEMIND-EGRESS &&
      iptables -t mangle -A HIVEMIND-EGRESS -d 35.235.240.0/20 -j RETURN &&
      iptables -t mangle -A HIVEMIND-EGRESS -d 169.254.169.254/32 -j RETURN &&
      iptables -t mangle -A HIVEMIND-EGRESS -j RETURN &&
      iptables -t mangle -A POSTROUTING -o ens4 -j HIVEMIND-EGRESS || return 1
    say "egress: counting internet-bound bytes (IAP and metadata server excluded)"
  fi
  # The chain's last rule matches whatever the two exclusions let through.
  iptables -t mangle -L HIVEMIND-EGRESS -v -x -n | tail -1 | awk '{ print $2 }'
}
month=$(TZ=America/Los_Angeles date +%Y-%m)
last_file="$STATE/tx-last"
if [ -n "$TX" ]; then
  raw=$(cat "$TX")
elif raw=$(internet_bytes) && case $raw in '' | *[!0-9]*) false ;; esac; then
  : # a number; anything else falls back below rather than ending the run
else
  raw=$(cat "$IFACE_TX")
  last_file="$STATE/tx-last-iface"
  say "egress: iptables counter unavailable; counting the interface total"
fi
last=$(cat "$last_file" 2>/dev/null || echo 0)
if [ "$raw" -ge "$last" ]; then delta=$((raw - last)); else delta=$raw; fi
total=$(($(cat "$STATE/egress-$month" 2>/dev/null || echo 0) + delta))
echo "$total" >"$STATE/egress-$month"
echo "$raw" >"$last_file"

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

# 4. Rate limit. Last, and never fatal: a failing iptables must not skip the
#    bounds above (errexit is off inside a function called with ||).
rate_limit() {
  installed=""
  for port in 22 23; do
    new="-p tcp -m conntrack --ctstate NEW --ctorigdstport $port"
    for rule in \
      "$new -m hashlimit --hashlimit-name cowrie-$port --hashlimit-mode srcip --hashlimit-srcmask $SRC_MASK --hashlimit-above $RATE_PER_MIN/minute --hashlimit-burst $RATE_BURST -j DROP" \
      "$new -m connlimit --connlimit-above $CONCURRENT --connlimit-mask $SRC_MASK -j DROP"; do
      # shellcheck disable=SC2086 # the rule is meant to word-split into arguments
      if ! iptables -C DOCKER-USER $rule 2>/dev/null; then
        iptables -I DOCKER-USER $rule || return 1
        installed=1
      fi
    done
  done
  if [ -n "$installed" ]; then
    date -u +%Y-%m-%dT%H:%M:%SZ >"$STATE/rate-limit-since.new"
    [ -f "$STATE/rate-limit-since" ] || mv "$STATE/rate-limit-since.new" "$STATE/rate-limit-since"
    rm -f "$STATE/rate-limit-since.new"
    say "rate limit: installed ($RATE_PER_MIN/min burst $RATE_BURST, $CONCURRENT concurrent, per /$SRC_MASK, ports 22/23)"
  fi
  if [ "${NOW_MINUTE:-$(date +%M)}" -lt 5 ]; then # once an hour (cron runs every 5 minutes)
    dropped=$(iptables -L DOCKER-USER -v -x -n | awk '$3 == "DROP" { n += $1 } END { print n + 0 }') || return 1
    say "rate limit: $dropped new connections dropped since the rules were (re)installed"
  fi
}
if [ "$RATE_LIMIT" = on ]; then
  rate_limit || say "rate limit: iptables failed; the rules may be missing"
fi
