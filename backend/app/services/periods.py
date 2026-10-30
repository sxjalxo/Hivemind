"""The windows a sensor's traffic is compared across (R2, used by R3).

A boundary is every persona deployment and every recorded change; a period is
the span between two boundaries, labelled with the persona in force. Pure.
"""

from dataclasses import dataclass
from datetime import datetime

from app.services.persona_deployments import PRE_PERSONA


@dataclass(frozen=True)
class Period:
    start: datetime
    end: datetime
    persona: str | None  # None: the sensor has never had a persona deployed
    opened_by: tuple[str, ...]  # "persona:<name>", "rate-limit", "note"; () for the first


def periods(deployments, changes, start: datetime, end: datetime) -> list[Period]:
    """Cut the window [start, end) into periods at every deployment and change.

    In effect the window is half-open: a deployment at `start` is in force for the
    first period and is not a boundary; anything before `start` or at/after `end`
    cuts nothing. `persona` is None only when the sensor has no deployment at all;
    one that lands after the window still makes the window `pre-persona`. A
    deployment and a change at the same instant form one boundary listing both.
    Two deployments at the same instant resolve to the later one in input order.
    """
    if end <= start:
        return []
    deployments = sorted(deployments, key=lambda d: d.deployed_at)
    persona = None
    for d in deployments:
        if d.deployed_at <= start:
            persona = d.persona
    if persona is None and any(d.deployed_at > start for d in deployments):
        persona = PRE_PERSONA  # a sensor that gets a persona later ran pre-persona before it
    cuts: dict[datetime, list[str]] = {}
    for d in deployments:
        if start < d.deployed_at < end:
            cuts.setdefault(d.deployed_at, []).append(f"persona:{d.persona}")
    for c in changes:
        if start < c.at < end:
            cuts.setdefault(c.at, []).append(c.kind)
    out, cursor, opened = [], start, ()
    for at in sorted(cuts):
        out.append(Period(cursor, at, persona, opened))
        for label in cuts[at]:
            if label.startswith("persona:"):
                persona = label.removeprefix("persona:")
        cursor, opened = at, tuple(cuts[at])
    out.append(Period(cursor, end, persona, opened))
    return out
