"""The persona experiment's schedule (roadmap R3): which arm is due, and whether it is in place.

The schedule is a committed YAML file the operator fills in when the experiment
begins. Pure apart from reading that file.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from app.services.persona_deployments import PRE_PERSONA

PERSONAS_DIR = Path(__file__).resolve().parents[4] / "infra" / "cowrie" / "personas"
SCHEDULE_PATH = PERSONAS_DIR / "experiment.yaml"
STOCK = "stock"  # the arm that runs the pre-persona setup (`deploy_persona --revert`)


class ScheduleError(ValueError):
    """The schedule cannot be used; nothing may be deployed from it."""


@dataclass(frozen=True)
class Slot:
    index: int
    arm: str
    start: datetime
    end: datetime


@dataclass(frozen=True)
class Schedule:
    sensor: str
    start: datetime
    block_days: int
    arms: tuple[str, ...]

    @property
    def slots(self) -> list[Slot]:
        span = timedelta(days=self.block_days)
        return [
            Slot(i, arm, self.start + i * span, self.start + (i + 1) * span)
            for i, arm in enumerate(self.arms)
        ]

    @property
    def end(self) -> datetime:
        return self.start + len(self.arms) * timedelta(days=self.block_days)


def persona_of(arm: str) -> str:
    """The `persona_deployments.persona` value an arm is recorded as."""
    return PRE_PERSONA if arm == STOCK else arm


def load_schedule(path: Path = SCHEDULE_PATH, personas_dir: Path = PERSONAS_DIR) -> Schedule:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ScheduleError(f"cannot read {path.name}: {type(exc).__name__}") from exc
    sensor = raw.get("sensor")
    if not sensor:
        raise ScheduleError("the schedule names no sensor")
    start = raw.get("start")
    if start is None:
        raise ScheduleError("the schedule has no start yet; set `start` to a UTC time to begin")
    if isinstance(start, str):
        try:
            start = datetime.fromisoformat(start)
        except ValueError:
            raise ScheduleError(f"start is not an ISO 8601 time: {start!r}") from None
    if not isinstance(start, datetime) or start.tzinfo is None:
        raise ScheduleError("start needs a timezone; end it with Z")
    days = raw.get("block_days")
    if not isinstance(days, int) or isinstance(days, bool) or days < 1:
        raise ScheduleError(f"block_days must be a whole number of days, at least 1: {days!r}")
    arms = [str(a) for a in raw.get("blocks") or []]
    if not arms:
        raise ScheduleError("the schedule lists no blocks")
    unknown = sorted(
        {a for a in arms if a != STOCK and not (personas_dir / a / "persona.yaml").is_file()}
    )
    if unknown:
        raise ScheduleError(f"unknown arms: {', '.join(unknown)}")
    return Schedule(str(sensor), start, days, tuple(arms))


def due(schedule: Schedule, at: datetime) -> Slot | None:
    """The slot scheduled at `at`: None before the start and from the end on."""
    return next((s for s in schedule.slots if s.start <= at < s.end), None)


def in_place(slot: Slot, deployments, at: datetime) -> bool:
    """True when the deployment in force at `at` was made inside the slot and runs its arm.

    A persona carried over from before the slot does not count, even the same one:
    every block must open with a recorded deployment and a freshly recreated Cowrie.
    """
    current = None
    for d in sorted(deployments, key=lambda d: d.deployed_at):
        if d.deployed_at <= at:
            current = d
    return (
        current is not None
        and current.deployed_at >= slot.start
        and current.persona == persona_of(slot.arm)
    )
