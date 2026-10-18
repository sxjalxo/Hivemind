#!/bin/sh
# Hivemind live honeypot: hand ports 22/23 to Cowrie. Idempotent.
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

# 2. Cowrie on 22 (SSH) and 23 (Telnet).
sudo docker rm -f cowrie >/dev/null 2>&1 || true
sudo docker run -d --name cowrie \
  --restart unless-stopped \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 350m --memory-swap 700m \
  --log-opt max-size=10m --log-opt max-file=3 \
  -p 22:2222 -p 23:2223 \
  -v /opt/hivemind/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro \
  -v /opt/hivemind/honeyfs:/honeyfs:ro \
  -v cowrie-logs:/cowrie/cowrie-git/var/log/cowrie \
  -v cowrie-tty:/cowrie/cowrie-git/var/lib/cowrie/tty \
  -v cowrie-dl:/cowrie/cowrie-git/var/lib/cowrie/downloads \
  "$IMAGE"
