#!/bin/sh
# Everything the home backend's evaluation key can do on this VM (checklist 24).
#
# Installed root-owned as /usr/local/sbin/hivemind-eval-gate and reached only
# through user hivemind-eval: its authorized_keys line forces
#   restrict,command="sudo -n /usr/local/sbin/hivemind-eval-gate"
# and a sudoers rule allows exactly this file, keeping SSH_ORIGINAL_COMMAND.
# What the client asks for arrives there as text, never as a command. Three
# requests are honoured, all on the EVALUATION Cowrie's volumes and never the
# live honeypot's:
#   list                      its cowrie.json files, as "inode size name"
#   read NAME START LENGTH    LENGTH bytes of one of them, from byte START
#   reset                     empty its tty and downloads volumes (keeping
#                             .gitignore), then fail unless they are empty --
#                             a reset that did not happen must not read as one
set -eu
set -f # the request is split into words below; none of them may glob
vol() { docker volume inspect -f '{{.Mountpoint}}' "$1"; }
refuse() {
  echo "refused: $*" >&2
  exit 2
}
number() { case $1 in '' | *[!0-9]* | 0?*) refuse "not a plain number: $1" ;; esac }

# shellcheck disable=SC2086 # splitting the request into words is the point
set -- ${SSH_ORIGINAL_COMMAND:-}
case "${1:-} $#" in
"list 1")
  cd "$(vol cowrie-eval-logs)"
  set +f
  stat -c '%i %s %n' cowrie.json* 2>/dev/null || true
  ;;
"read 4")
  case $2 in
  cowrie.json | cowrie.json.[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
  *) refuse "file name: $2" ;;
  esac
  number "$3"
  number "$4"
  cd "$(vol cowrie-eval-logs)"
  tail -c +$(($3 + 1)) "$2" | head -c "$4"
  ;;
"reset 1")
  for v in cowrie-eval-tty cowrie-eval-dl; do
    d=$(vol "$v")
    find "$d" -mindepth 1 -maxdepth 1 ! -name .gitignore -exec rm -rf {} +
    left=$(find "$d" -mindepth 1 -maxdepth 1 ! -name .gitignore | head -n 1)
    if [ -n "$left" ]; then
      echo "not cleared: $left" >&2
      exit 1
    fi
  done
  ;;
*) refuse "${SSH_ORIGINAL_COMMAND:-<nothing>}" ;;
esac
