#!/bin/sh
# Hivemind on the VM: the live honeypot on 22/23 and, for the evaluation half
# (checklist 24), a second Cowrie on 2222. Idempotent.
#   ./run-cowrie.sh        (re)create both
#   ./run-cowrie.sh eval   (re)create only the evaluation one; the live
#                          honeypot keeps running
#
# The real sshd keeps only 50022 (GCP rule allow-admin-ssh, owner IP only).
# Cowrie runs as its image's non-root user with no capabilities; Docker
# publishes it on the host's 22 and 23, so no iptables rules are needed.
# Its stdout is Cowrie's text log; Docker's json-file driver keeps that forever
# unless capped, hence the --log-opt below.
#
# Deploy (from the repo root, admin key; honeyfs is the hardened arm's):
#   scp -P 50022 -i KEY -r infra/wild-vm/* infra/cowrie/matrix/hardened/honeyfs USER@VM:/opt/hivemind/
#   then on the VM:
#   sed -i 's/\r$//' /opt/hivemind/*.sh /opt/hivemind/*.cron && chmod 755 /opt/hivemind/*.sh
#   sudo install -m 644 /opt/hivemind/hivemind-guard.cron /etc/cron.d/hivemind-guard
#   /opt/hivemind/run-cowrie.sh
set -eu
cd /opt/hivemind
IMAGE=$(cat image.txt)
DROPIN=/etc/ssh/sshd_config.d/10-hivemind-admin.conf

# 1. Real sshd off port 22 -- validated before the restart, so a bad edit can
#    never leave sshd unable to start.
if grep -q '^Port 22$' "$DROPIN"; then
  sudo sed -i '/^Port 22$/d' "$DROPIN"
  sudo sed -i 's/^# Port 22 is temporary.*$/# Port 22 belongs to Cowrie (run-cowrie.sh); 50022 is the admin port./' "$DROPIN"
  sudo sshd -t
  sudo systemctl restart ssh.service
fi

# start NAME MEMORY PORTS...: (re)create one Cowrie from this config, with
# volumes NAME-logs, NAME-tty and NAME-dl of its own.
start() {
  name=$1 memory=$2
  shift 2
  sudo docker rm -f "$name" >/dev/null 2>&1 || true
  sudo docker run -d --name "$name" \
    --restart unless-stopped \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --memory "$memory" --memory-swap "$((${memory%m} * 2))m" \
    --log-opt max-size=10m --log-opt max-file=3 \
    "$@" \
    -v /opt/hivemind/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro \
    -v /opt/hivemind/honeyfs:/honeyfs:ro \
    -v "$name-logs":/cowrie/cowrie-git/var/log/cowrie \
    -v "$name-tty":/cowrie/cowrie-git/var/lib/cowrie/tty \
    -v "$name-dl":/cowrie/cowrie-git/var/lib/cowrie/downloads \
    "$IMAGE"
}

# 2. The live honeypot on 22 (SSH) and 23 (Telnet).
if [ "${1:-}" != eval ]; then
  start cowrie 350m -p 22:2222 -p 23:2223
fi

# 3. The evaluation Cowrie: same image, config and persona, SSH only, on 2222,
#    which the GCP rule opens to the owner's IP alone. Its volumes are its own,
#    so its reset (eval-gate.sh) can never reach the live honeypot's evidence,
#    and evaluation sessions never land in gcp-wild-01. Recreating it gives it
#    new SSH host keys: the next run fingerprints as a different honeypot.
start cowrie-eval 250m -p 2222:2222
