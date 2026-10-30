"""Report the persona experiment (R3) from the recorded data. Changes nothing.

    python -m scripts.persona_experiment              # as of now; INTERIM until the last block ends
    python -m scripts.persona_experiment --now 2026-12-08T00:00:00Z

Reads infra/cowrie/personas/experiment.yaml, the local database (deployments, sensor
changes) and Elasticsearch. Save the final run from PowerShell with
`... | Out-File -Encoding utf8 ..\\docs\\paper\\rerun\\14-persona-experiment.txt`
(a bare `>` writes UTF-16).
"""

import argparse
import asyncio
import contextlib
import sys
from datetime import UTC, datetime
from pathlib import Path

from app.services.experiment.schedule import SCHEDULE_PATH, ScheduleError, load_schedule
from scripts.record_change import _when


async def _main(schedule, now: datetime) -> str:
    """One event loop for the run: the pooled engine and the ES client are bound to it."""
    from app.db.session import get_engine
    from app.es.client import get_es
    from app.services.experiment.report import build, render

    try:
        return render(await build(schedule, now))
    finally:
        with contextlib.suppress(Exception):
            await get_engine().dispose()
        with contextlib.suppress(Exception):
            await get_es().close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--now", type=_when, help="report as of this time (ISO 8601, with a zone)")
    parser.add_argument("--schedule", type=Path, default=SCHEDULE_PATH, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        schedule = load_schedule(args.schedule)
    except ScheduleError as exc:
        print(f"schedule: {exc}", file=sys.stderr)
        return 1
    now = args.now or datetime.now(UTC)
    if now <= schedule.start:
        print(f"not started: the experiment begins {schedule.start.isoformat()}")
        return 0
    print(asyncio.run(_main(schedule, now)), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
