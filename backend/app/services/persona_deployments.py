"""Which persona each sensor runs, and from when (roadmap R1).

Written only by `scripts/deploy_persona.py`; read by the evaluation run (the
remote honeypot fingerprint) and, later, the per-sensor page and the persona
experiment. History, never edited.
"""

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select

from app.db.models import PersonaDeployment
from app.db.session import get_session_factory

# Recorded by `deploy_persona --revert`: the sensor is back on the hardened setup it
# ran before any persona, so it must fingerprint as it did then.
PRE_PERSONA = "pre-persona"


async def record(
    honeypot_ids: Sequence[str],
    persona: str,
    digest: str,
    deployed_by: str,
    at: datetime | None = None,
) -> None:
    """One row per sensor, one transaction: a twinned deploy is never half-recorded."""
    when = at or datetime.now(UTC)
    async with get_session_factory()() as db:
        db.add_all(
            PersonaDeployment(
                honeypot_id=sensor,
                persona=persona,
                digest=digest,
                deployed_by=deployed_by,
                deployed_at=when,
            )
            for sensor in honeypot_ids
        )
        await db.commit()


async def active(honeypot_id: str, at: datetime | None = None) -> PersonaDeployment | None:
    """The deployment in force at `at` (default now), or None before the first."""
    query = (
        select(PersonaDeployment)
        .where(PersonaDeployment.honeypot_id == honeypot_id)
        .where(PersonaDeployment.deployed_at <= (at or datetime.now(UTC)))
        .order_by(PersonaDeployment.deployed_at.desc())
        .limit(1)
    )
    async with get_session_factory()() as db:
        return (await db.execute(query)).scalar_one_or_none()


async def history(honeypot_id: str) -> list[PersonaDeployment]:
    """Oldest first."""
    query = (
        select(PersonaDeployment)
        .where(PersonaDeployment.honeypot_id == honeypot_id)
        .order_by(PersonaDeployment.deployed_at, PersonaDeployment.id)
    )
    async with get_session_factory()() as db:
        return list((await db.execute(query)).scalars())


async def active_digest(honeypot_id: str) -> str | None:
    row = await active(honeypot_id)
    return row.digest if row and row.persona != PRE_PERSONA else None
