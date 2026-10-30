"""Non-persona configuration changes of a sensor, such as a rate limit switched on.

Written only by `scripts/record_change.py`; read by the per-sensor page, which cuts
a sensor's history into periods at each change. History, never edited.
"""

from datetime import UTC, datetime

from sqlalchemy import select

from app.db.models import SensorChange
from app.db.session import get_session_factory

KINDS = ("rate-limit", "note")


async def record(
    honeypot_id: str,
    kind: str,
    detail: str,
    recorded_by: str,
    at: datetime | None = None,
) -> None:
    if kind not in KINDS:
        raise ValueError(f"unknown change kind {kind!r}; expected one of {KINDS}")
    async with get_session_factory()() as db:
        db.add(
            SensorChange(
                honeypot_id=honeypot_id,
                at=at or datetime.now(UTC),
                kind=kind,
                detail=detail,
                recorded_by=recorded_by,
            )
        )
        await db.commit()


async def history(honeypot_id: str) -> list[SensorChange]:
    """Oldest first."""
    query = (
        select(SensorChange)
        .where(SensorChange.honeypot_id == honeypot_id)
        .order_by(SensorChange.at, SensorChange.id)
    )
    async with get_session_factory()() as db:
        return list((await db.execute(query)).scalars())
