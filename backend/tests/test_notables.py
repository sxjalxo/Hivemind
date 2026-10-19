"""The notables feed. Rows are written directly so the model decides nothing here.

Technique ids are made up (`T99xx`), so no real mapping already in the database
can make a "first seen" assertion pass or fail by accident.
"""

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete

from app.db.models import Analysis, TechniqueMapping
from app.db.session import get_session_factory
from app.seed.seeder import seed
from app.services.notables import list_notables

NOW = datetime.now(UTC)


def _analysis(session_id: str, risk: str, created: datetime, classification: str) -> Analysis:
    return Analysis(
        started_by="unrecorded",
        id=uuid.uuid4(),
        session_id=session_id,
        model="test-fixture",
        analysis_type="behavioral",
        status="completed",
        created_at=created,
        duration_seconds=0,
        classification=classification,
        confidence=0.5,
        risk_score=90 if risk in ("high", "critical") else 10,
        risk=risk,
        behavior_summary="fixture",
        model_tier="local",
        prompt_version="test",
    )


def _mapping(analysis: Analysis, technique: str, source: str, when: datetime) -> TechniqueMapping:
    return TechniqueMapping(
        analysis_id=analysis.id,
        technique_id=technique,
        technique_name="Fixture technique",
        tactic="Execution",
        confidence=1.0,
        source=source,
        rule_id="fixture-rule" if source == "rule" else None,
        timestamp=when,
    )


@asynccontextmanager
async def _rows(*rows):
    factory = get_session_factory()
    analyses = [r.id for r in rows if isinstance(r, Analysis)]
    async with factory() as db:
        for row in rows:
            if isinstance(row, Analysis):
                db.add(row)
        await db.flush()
        for row in rows:
            if isinstance(row, TechniqueMapping):
                db.add(row)
        await db.commit()
    try:
        yield
    finally:
        async with factory() as db:
            await db.execute(
                delete(TechniqueMapping).where(TechniqueMapping.analysis_id.in_(analyses))
            )
            await db.execute(delete(Analysis).where(Analysis.id.in_(analyses)))
            await db.commit()


async def test_a_recent_high_risk_session_is_notable_once_and_as_an_inference() -> None:
    sid = f"test-notable-{uuid.uuid4().hex[:8]}"
    older = _analysis(sid, "high", NOW - timedelta(hours=2), "first pass")
    latest = _analysis(sid, "critical", NOW - timedelta(minutes=5), "latest pass")
    stale = _analysis(f"{sid}-old", "critical", NOW - timedelta(days=30), "outside window")
    calm = _analysis(f"{sid}-low", "low", NOW, "not notable")

    async with _rows(older, latest, stale, calm):
        mine = [
            n for n in await list_notables(days=7) if n.session_id and n.session_id.startswith(sid)
        ]

    assert [n.session_id for n in mine] == [sid], "one per session, recent, high/critical only"
    assert mine[0].title == "Critical risk: latest pass"
    assert mine[0].provenance == "AI INFERENCE"


async def test_only_a_first_rule_backed_sighting_inside_the_window_is_notable() -> None:
    sid = f"test-notable-{uuid.uuid4().hex[:8]}"
    a = _analysis(sid, "low", NOW, "fixture")
    rows = (
        a,
        _mapping(a, "T9901", "rule", NOW - timedelta(hours=1)),  # new: notable
        _mapping(a, "T9902", "rule", NOW - timedelta(hours=1)),  # seen 30 days ago: not
        _mapping(a, "T9902", "rule", NOW - timedelta(days=30)),
        _mapping(a, "T9903", "llm", NOW - timedelta(hours=1)),  # an inference: never
    )
    async with _rows(*rows):
        techniques = {n.technique_id: n for n in await list_notables(days=7) if n.technique_id}

    assert "T9901" in techniques
    assert techniques["T9901"].provenance == "OBSERVED"
    assert "T9902" not in techniques
    assert "T9903" not in techniques


async def test_a_denied_sensor_and_an_unplaceable_session_are_both_withheld() -> None:
    await seed(reset=True)  # seed-recon-01 is recorded by cowrie-01
    unplaced = f"test-notable-{uuid.uuid4().hex[:8]}"
    rows = (
        _analysis("seed-recon-01", "critical", NOW, "fixture on a real session"),
        _analysis(unplaced, "critical", NOW, "fixture with no events"),
    )
    async with _rows(*rows):
        open_ids = {n.session_id for n in await list_notables(days=7)}
        scoped = {n.session_id for n in await list_notables(days=7, deny_honeypots={"cowrie-01"})}
        other = {n.session_id for n in await list_notables(days=7, deny_honeypots={"elsewhere"})}

    assert {"seed-recon-01", unplaced} <= open_ids
    assert "seed-recon-01" not in scoped
    # Under any scope, a session that cannot be placed on a sensor is not shown.
    assert unplaced not in other
    assert "seed-recon-01" in other


async def test_a_burst_of_high_risk_sessions_cannot_hide_a_first_sighting() -> None:
    """A plain newest-50 list let 48 freshly analysed high-risk sessions push a
    first-ever technique sighting off the bell (2026-10-19)."""
    sid = f"test-notable-{uuid.uuid4().hex[:8]}"
    first = _analysis(sid, "low", NOW - timedelta(hours=2), "fixture")
    burst = [
        _analysis(f"{sid}-{i}", "critical", NOW - timedelta(minutes=i), "burst") for i in range(60)
    ]
    rows = (first, *burst, _mapping(first, "T9904", "rule", NOW - timedelta(hours=2)))
    async with _rows(*rows):
        notables = await list_notables(days=7)

    assert "T9904" in {n.technique_id for n in notables}
    assert len(notables) <= 50
