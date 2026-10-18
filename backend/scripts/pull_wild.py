"""Pull the live honeypot's Cowrie log home, for Filebeat to ship (honeypot.id gcp-wild-01).

    docker compose --profile wild up -d wild-pull        # every 5 min, as a service
    python -m scripts.pull_wild --once                   # one pull, from backend/
    (a --once beside the running service is refused: they share one position file)

The VM keeps its own log and accepts no inbound traffic but the owner's SSH, so
the logs are PULLED: this connects to that sshd, reads only the bytes appended
since the last pull, and appends them to one local file that never rotates.
Filebeat follows that file like any other honeypot's log. How a pull stays
exactly-once is in `app.services.wild_pull`.

Configuration is environment only (see the `wild-pull` service in
docker-compose.yml); nothing about the VM is hard-coded. The VM's SSH host key
is pinned (`WILD_HOST_KEY`).
"""

import argparse
import logging
import os
import time
from pathlib import Path

from app.services.wild_pull import PullerBusy, Remote, locked, pull_once

log = logging.getLogger("pull_wild")


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
    try:
        with locked(out_dir):
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
    except PullerBusy as exc:
        raise SystemExit(f"{exc}; stop it first") from None


if __name__ == "__main__":
    main()
