"""Record a non-persona configuration change of a sensor, e.g. a rate limit switched on.

    python -m scripts.record_change gcp-wild-01 "22/23 limited to 10 per minute per /24" \
        --kind rate-limit --at 2026-10-25T09:30:00Z

--at defaults to now. It writes to the local database only; nothing is contacted.
"""

import argparse
import asyncio
import contextlib
import getpass
import sys
from datetime import UTC, datetime

from app.services.sensor_changes import KINDS


def _when(text: str) -> datetime:
    try:
        when = datetime.fromisoformat(text)  # 3.11+ accepts a trailing Z
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an ISO 8601 time: {text!r}") from None
    if when.tzinfo is None:
        raise argparse.ArgumentTypeError(f"{text!r} has no timezone; end it with Z or +HH:MM")
    return when


async def _main(args: argparse.Namespace) -> None:
    """One event loop for the run: the pooled engine is bound to it."""
    from app.db.session import get_engine
    from app.services import sensor_changes

    try:
        await sensor_changes.record(
            args.honeypot_id,
            args.kind,
            args.detail,
            f"operator:{getpass.getuser()}",
            args.at or datetime.now(UTC),
        )
    finally:
        with contextlib.suppress(Exception):
            await get_engine().dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("honeypot_id")
    parser.add_argument("detail")
    parser.add_argument("--kind", choices=KINDS, default="note")
    parser.add_argument("--at", type=_when, help="ISO 8601 with a timezone; default now")
    args = parser.parse_args(argv)
    asyncio.run(_main(args))
    print(f"recorded {args.kind} on {args.honeypot_id}: {args.detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
