import logging
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.db.models import (
    Analysis,
    EvidenceRef,
    ObservedBehavior,
    ParentType,
    RecommendedAction,
    SuspiciousIndicator,
    TechniqueMapping,
)
from app.db.session import get_session_factory
from app.services.llm.schemas import EvidenceCitation

logger = logging.getLogger(__name__)

_MODEL_BY_KIND = {
    ParentType.TECHNIQUE_MAPPING: TechniqueMapping,
    ParentType.OBSERVED_BEHAVIOR: ObservedBehavior,
    ParentType.SUSPICIOUS_INDICATOR: SuspiciousIndicator,
}


class UngroundedClaimError(RuntimeError):
    """A derived claim arrived with no resolvable evidence.

    Raised internally, per claim, by ``persist_analysis`` and caught in the
    same loop iteration: the claim is dropped and counted rather than
    propagated, so one hallucinated claim never aborts the rest of the
    analysis. Public so call sites and tests can recognize the failure mode
    by name.
    """


class NaiveTimestampError(ValueError):
    """An ``event_timestamps`` value has no timezone attached.

    ``EvidenceRef.timestamp`` is ``DateTime(timezone=True)``. Handing
    asyncpg a tz-aware value against a tz-naive column raises loudly, but
    the reverse — a tz-naive Python value against this tz-aware column —
    does not: Postgres silently reinterprets it in the DB session's local
    timezone, storing a different instant than intended with no error. That
    breaks the one thing ``EvidenceRef.timestamp`` exists for: tying a claim
    back to the exact moment its event occurred. So this is checked and
    rejected here, loudly, before any value from ``event_timestamps``
    reaches the database — never coerced or assumed-UTC, since a guess would
    just be a different flavor of the same silent corruption.
    """


def _require_aware_timestamps(event_timestamps: dict[str, datetime]) -> None:
    for event_id, ts in event_timestamps.items():
        if ts.tzinfo is None or ts.utcoffset() is None:
            raise NaiveTimestampError(
                f"event_timestamps[{event_id!r}] is a naive datetime ({ts!r}); "
                "evidence timestamps must be timezone-aware, or Postgres will "
                "silently reinterpret them in the session's local timezone."
            )


class Claim(BaseModel):
    """A derived claim awaiting the evidence barrier.

    ``kind`` selects the destination table via ``_MODEL_BY_KIND``. ``payload``
    is passed as keyword arguments to that table's model — its keys must
    match the model's columns exactly (minus ``analysis_id``, which
    ``persist_analysis`` supplies). ``evidence`` is the citation list the
    barrier checks against ``event_timestamps`` before anything is written.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    kind: ParentType
    payload: dict
    evidence: list[EvidenceCitation]


async def persist_analysis(
    analysis: Analysis,
    claims: list[Claim],
    actions: list[dict],
    session_id: str,
    event_timestamps: dict[str, datetime],
    prior_rejected: int = 0,
) -> int:
    """Write an analysis and every grounded claim in one transaction.

    This is the only place claim rows are written. A claim is grounded when
    at least one of its citations names an event id present in
    ``event_timestamps`` — i.e. an event that actually exists in this
    session. Citations that don't resolve are dropped from a claim that is
    otherwise grounded; a claim with zero resolving citations is dropped
    entirely and counted in the return value, never written.

    Each claim's row and its evidence rows are written in the same
    transaction as ``analysis`` itself. If any write fails partway through,
    the whole transaction rolls back — nothing commits, so there is no
    window where an evidence row can outlive, or a claim row can lack, its
    parent. That atomicity is the only integrity guarantee for
    ``evidence_refs.parent_id``, which carries no foreign key because it is
    polymorphic across four claim tables.

    ``RecommendedAction`` rows (``actions``) are exempt from the barrier:
    they are advice about what to do next, not a claim about what happened,
    so they are written unconditionally and never counted as rejected.

    Returns the number of claims rejected during this call. The analysis's
    stored ``rejected_claims`` is set to ``prior_rejected`` plus that count,
    so the value accumulates across the phases that call this function.

    Raises ``NaiveTimestampError`` if any value in ``event_timestamps`` lacks
    timezone info — checked before any database session is opened, so a bad
    caller never gets a half-open transaction.
    """
    _require_aware_timestamps(event_timestamps)

    rejected = 0
    factory = get_session_factory()

    async with factory() as db:
        db.add(analysis)
        await db.flush()

        for claim in claims:
            grounded = [c for c in claim.evidence if c.event_id in event_timestamps]
            try:
                if not grounded:
                    # Structural facts only -- kind, session, and how many
                    # citations failed to ground. Never claim.payload: it is
                    # freeform LLM-derived text that can echo attacker command
                    # text verbatim, and logging it would (a) let an
                    # attacker-influenced label forge log lines via embedded
                    # control characters, and (b) leak content from a claim
                    # we deliberately chose not to store.
                    raise UngroundedClaimError(
                        f"rejected claim: kind={claim.kind.value} "
                        f"session={session_id} cited={len(claim.evidence)} resolved=0"
                    )
            except UngroundedClaimError as exc:
                logger.warning("%s", exc)
                rejected += 1
                continue

            model = _MODEL_BY_KIND[claim.kind]
            row = model(analysis_id=analysis.id, **claim.payload)
            db.add(row)
            await db.flush()

            for citation in grounded:
                db.add(
                    EvidenceRef(
                        es_event_id=citation.event_id,
                        session_id=session_id,
                        timestamp=event_timestamps[citation.event_id],
                        artifact=citation.artifact,
                        parent_type=claim.kind,
                        parent_id=row.id,
                    )
                )

        for action in actions:
            db.add(RecommendedAction(analysis_id=analysis.id, **action))

        analysis.rejected_claims = prior_rejected + rejected
        db.add(analysis)
        await db.commit()

    return rejected


async def load_evidence(parent_type: ParentType, parent_id: uuid.UUID) -> list[EvidenceRef]:
    """Load every evidence row citing a given claim row."""
    factory = get_session_factory()
    async with factory() as db:
        return (
            (
                await db.execute(
                    select(EvidenceRef).where(
                        EvidenceRef.parent_type == parent_type,
                        EvidenceRef.parent_id == parent_id,
                    )
                )
            )
            .scalars()
            .all()
        )
