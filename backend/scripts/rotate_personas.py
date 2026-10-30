"""Deploy the persona the experiment schedule says is due on the live honeypot (R3).

    python -m scripts.rotate_personas            # dry run: what is due, what runs now
    python -m scripts.rotate_personas --apply    # deploy it through deploy_persona

Reads infra/cowrie/personas/experiment.yaml and the local database. Run it at each
block boundary; when the due block is already in place it changes nothing. A late
switch is fine: the analysis uses the recorded deployment times, not the schedule's.
"""

import argparse
import asyncio
import contextlib
import sys
from datetime import UTC, datetime

from app.services.experiment.schedule import (
    STOCK,
    ScheduleError,
    due,
    in_place,
    load_schedule,
)
from app.services.persona_deployments import PRE_PERSONA
from scripts import deploy_persona


def _t(at: datetime) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%d %H:%MZ")


async def _history(sensor: str):
    """One event loop for the read: the pooled engine is bound to it."""
    from app.db.session import get_engine
    from app.services import persona_deployments

    try:
        return await persona_deployments.history(sensor)
    finally:
        with contextlib.suppress(Exception):
            await get_engine().dispose()


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true", help="deploy; without it, a dry run")
    args = parser.parse_args(argv)
    now = now or datetime.now(UTC)

    try:
        schedule = load_schedule()
    except ScheduleError as exc:
        print(f"schedule: {exc}; nothing was changed", file=sys.stderr)
        return 1
    if now < schedule.start:
        print(f"not started: block 1 ({schedule.arms[0]}) starts {_t(schedule.start)}")
        return 0
    slot = due(schedule, now)
    if slot is None:
        print(f"experiment over at {_t(schedule.end)}; {schedule.arms[-1]} stays")
        return 0

    try:
        deployments = asyncio.run(_history(schedule.sensor))
    except Exception as exc:  # noqa: BLE001
        print(
            "the local database is not reachable (or not migrated): "
            f"{type(exc).__name__}; nothing was changed",
            file=sys.stderr,
        )
        return 1
    in_force = [d for d in deployments if d.deployed_at <= now]
    running = "nothing recorded"
    if in_force:
        latest = max(in_force, key=lambda d: d.deployed_at)
        name = STOCK if latest.persona == PRE_PERSONA else latest.persona
        running = f"{name} since {_t(latest.deployed_at)}"
    print(
        f"due: block {slot.index + 1} of {len(schedule.arms)}, {slot.arm}, "
        f"{_t(slot.start)} -> {_t(slot.end)}"
    )
    print(f"running on {schedule.sensor}: {running}")
    if in_place(slot, deployments, now):
        print(f"in place; next switch {_t(slot.end)}")
        return 0
    deploy_args = ["--revert"] if slot.arm == STOCK else [slot.arm]
    if not args.apply:
        print(f"would run: python -m scripts.deploy_persona {' '.join(deploy_args)} --apply")
        print(f"next switch {_t(slot.end)}")
        return 0
    return deploy_persona.main([*deploy_args, "--apply"])


if __name__ == "__main__":
    sys.exit(main())
