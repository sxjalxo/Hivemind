from datetime import date, datetime
from typing import Literal

from app.serialization import CamelModel


class Described(CamelModel):
    """A derived value and where it came from; `unknown` says nothing could be derived."""

    value: str
    source: Literal["observed", "persona", "evaluation", "unknown"]


class PeriodOut(CamelModel):
    start: datetime
    end: datetime
    persona: str | None
    opened_by: list[str]


class DeploymentOut(CamelModel):
    persona: str
    digest: str
    deployed_at: datetime
    deployed_by: str


class ChangeOut(CamelModel):
    kind: str
    detail: str
    at: datetime
    recorded_by: str


class SensorProfile(CamelModel):
    id: str
    name: str
    protocols: dict[str, int]
    address: str
    first_seen: datetime
    last_seen: datetime
    type: Described
    os: Described
    deployments: list[DeploymentOut]
    changes: list[ChangeOut]
    periods: list[PeriodOut]


class DayPoint(CamelModel):
    """One UTC day. Distinct counts are per day, so they are not additive across days."""

    day: date
    events: int
    sessions: int
    sources: int


class SourceOut(CamelModel):
    ip: str
    country: str | None
    events: int


class PeriodTraffic(CamelModel):
    period: PeriodOut
    events: int
    sessions: int
    sources: int
    events_per_day: float
    sessions_per_day: float
    sources_per_day: float


class SensorTraffic(CamelModel):
    """Traffic over the last `days`, on UTC days.

    `days=N` yields N+1 points, the first and last being partial days. Sessions
    and sources are approximate (HyperLogLog): above 3,000 per day, 10,000 per period.
    Per-period rates divide by the period's length in days (at least an hour).
    Events and sessions grow with that length, so their rates compare across
    periods; distinct sources grow more slowly (repeat sources), so
    `sources_per_day` does not compare between periods of different length.
    The periods start no earlier than the sensor's first event.
    """

    days: int
    per_day: list[DayPoint]
    top_sources: list[SourceOut]
    protocols: dict[str, int]
    periods: list[PeriodTraffic]


class TechniqueOut(CamelModel):
    """A rulebook technique the sensor's commands matched. `technique_id` is the rule's id."""

    technique_id: str
    name: str
    tactic: str
    rule_id: str
    events: int
    sessions: int
    first_seen: datetime
    last_seen: datetime
    per_period: list[int]


class SensorTechniques(CamelModel):
    """Techniques the deterministic rulebook finds in every distinct command received in the
    last `days` (observed, rule-matched; no model). `per_period` follows `periods`.

    Commands are matched as distinct strings, so only those up to 1024 characters (the
    keyword field's limit) are considered. `truncated` says that more distinct commands
    existed than were considered. Sessions are approximate (HyperLogLog) above the
    precision threshold.
    """

    days: int
    commands_considered: int
    truncated: bool
    periods: list[PeriodOut]
    techniques: list[TechniqueOut]
