#!/bin/sh
# One-time, on the VM as the admin user: the account the home backend's
# evaluation key logs in as, able to run eval-gate.sh and nothing else.
#   ./setup-eval-gate.sh "ssh-ed25519 AAAA... hivemind-eval"
# Re-running it replaces the key and reinstalls the gate.
set -eu
cd /opt/hivemind
case "${1:-}" in
"ssh-ed25519 "*) ;;
*)
  echo "pass the evaluation key's public line: ssh-ed25519 AAAA... hivemind-eval" >&2
  exit 2
  ;;
esac

# The gate, root-owned so the restricted user cannot change what it allows.
sudo install -m 755 -o root -g root eval-gate.sh /usr/local/sbin/hivemind-eval-gate

# The user. A '*' password is not a lock: OpenSSH refuses key logins to a
# locked account on some setups, and there is no password either way.
id hivemind-eval >/dev/null 2>&1 || sudo useradd --create-home --shell /bin/sh hivemind-eval
sudo usermod -p '*' hivemind-eval

# Its key may only run the gate: no shell, no forwarding, no pty.
sudo install -d -m 700 -o hivemind-eval -g hivemind-eval /home/hivemind-eval/.ssh
keys=/home/hivemind-eval/.ssh/authorized_keys
printf 'restrict,command="sudo -n /usr/local/sbin/hivemind-eval-gate" %s\n' "$1" |
  sudo tee "$keys" >/dev/null
sudo chown hivemind-eval:hivemind-eval "$keys"
sudo chmod 600 "$keys"

# sudo for exactly the gate, keeping the request it reads. Checked BEFORE it is
# installed: a broken file in sudoers.d breaks sudo for the admin user too.
rule=$(mktemp)
printf '%s\n' \
  'Defaults!/usr/local/sbin/hivemind-eval-gate env_keep += "SSH_ORIGINAL_COMMAND"' \
  'hivemind-eval ALL=(root) NOPASSWD: /usr/local/sbin/hivemind-eval-gate' >"$rule"
sudo visudo -cf "$rule"
sudo install -m 440 -o root -g root "$rule" /etc/sudoers.d/hivemind-eval
rm -f "$rule"
echo "hivemind-eval can now run the gate and nothing else"
