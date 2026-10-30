"""What the persona experiment reads (R3): blocks as they ran, coverage, sessions.

Blocks come from the recorded deployments, never from the schedule's times: a late
switch lengthens one block and shortens the next, and the report shows it. Sensor
changes do not cut blocks (the report lists them as possible confounds).
"""

import math
from dataclasses import dataclass
from datetime import datetime

from app.config import get_settings
from app.es.client import get_es
from app.services import persona_deployments
from app.services.experiment.schedule import STOCK, Schedule
from app.services.experiment.sessions import ACTIONS, Event, SessionStats, summarize
from app.services.periods import periods
from app.services.persona_deployments import PRE_PERSONA

_PAGE = 5_000
_KEEP_ALIVE = "5m"
_FIELDS = ["@timestamp", "event.action", "session.id", "process.command_line", "file.url"]


@dataclass(frozen=True)
class Block:
    """A stretch of the experiment window under one deployment, as it actually ran."""

    start: datetime
    end: datetime
    arm: str | None  # None: the sensor has no deployment recorded at all
    opened_by_deployment: bool

    @property
    def hours(self) -> float:
        return (self.end - self.start).total_seconds() / 3600


def window(schedule: Schedule, now: datetime) -> tuple[datetime, datetime]:
    return schedule.start, min(now, schedule.end)


async def blocks_as_run(schedule: Schedule, now: datetime) -> list[Block]:
    """The window cut at every recorded deployment of the sensor."""
    start, end = window(schedule, now)
    deployments = await persona_deployments.history(schedule.sensor)
    deployed_at = {d.deployed_at for d in deployments}
    return [
        Block(
            p.start,
            p.end,
            None if p.persona is None else STOCK if p.persona == PRE_PERSONA else p.persona,
            p.start in deployed_at,
        )
        for p in periods(deployments, [], start, end)
    ]


def _in(sensor: str, start: datetime, end: datetime) -> list[dict]:
    return [
        {"term": {"honeypot.id": sensor}},
        {"range": {"@timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}},
    ]


async def coverage(sensor: str, start: datetime, end: datetime) -> tuple[int, int]:
    """(UTC hours holding at least one event of the sensor, UTC hours overlapping the span)."""
    first_hour = start.replace(minute=0, second=0, microsecond=0)
    total = math.ceil((end - first_hour).total_seconds() / 3600)
    response = await get_es().search(
        index=get_settings().es_index,
        size=0,
        query={"bool": {"filter": _in(sensor, start, end)}},
        aggs={
            "hours": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 1,
                }
            }
        },
    )
    return len(response["aggregations"]["hours"]["buckets"]), total


async def read_sessions(
    sensor: str, start: datetime, end: datetime
) -> tuple[list[SessionStats], int]:
    """Every session with an event in [start, end), built from those events; and events read.

    A point-in-time keeps the pages consistent while wild-pull keeps indexing; sorting
    by session, then time, hands each session's events over together and in order.
    No cap: this is an offline report.
    """
    es = get_es()
    pit = (await es.open_point_in_time(index=get_settings().es_index, keep_alive=_KEEP_ALIVE))["id"]
    query = {
        "bool": {
            "filter": [
                *_in(sensor, start, end),
                {"terms": {"event.action": list(ACTIONS)}},
                {"exists": {"field": "session.id"}},
            ]
        }
    }
    sessions: list[SessionStats] = []
    current: str | None = None
    events: list[Event] = []
    read = 0
    after = None
    try:
        while True:
            response = await es.search(
                pit={"id": pit, "keep_alive": _KEEP_ALIVE},
                size=_PAGE,
                query=query,
                sort=[{"session.id": "asc"}, {"@timestamp": "asc"}],
                source=_FIELDS,
                search_after=after,
            )
            pit = response["pit_id"]
            hits = response["hits"]["hits"]
            if not hits:
                break
            for hit in hits:
                source = hit["_source"]
                session_id = source["session"]["id"]
                if session_id != current:
                    if events:
                        sessions.append(summarize(current, events))
                    current, events = session_id, []
                events.append(
                    Event(
                        datetime.fromisoformat(source["@timestamp"]),
                        source["event"]["action"],
                        (source.get("process") or {}).get("command_line"),
                        (source.get("file") or {}).get("url"),
                    )
                )
            read += len(hits)
            after = hits[-1]["sort"]
    finally:
        await es.close_point_in_time(id=pit)
    if events:
        sessions.append(summarize(current, events))
    return sessions, read
