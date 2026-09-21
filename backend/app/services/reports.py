import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from app.auth import Actor
from app.db.models import Report as ReportRow
from app.db.session import get_session_factory
from app.models.report import (
    AttackerBehavior,
    IncidentOverview,
    ThreatAssessment,
    ThreatReport,
)
from app.services.analyzer import latest_for_session, run_analysis
from app.services.intel import list_indicators
from app.services.session_builder import build_timeline, get_session


async def create_report(session_id: str, actor: Actor | None = None) -> ThreatReport:
    """Assemble a report from the session's latest analysis.

    If the session has never been analyzed, analyze it first — a report
    without an analysis would have nothing to say.
    """
    analysis = await latest_for_session(session_id)
    if analysis is None:
        # The analysis this triggers is credited to whoever asked for the
        # report -- it is the same action from the operator's side, and
        # recording it as `unrecorded` would put a hole in the trail at
        # exactly the point where one request did two things.
        await run_analysis(session_id, actor=actor)
        analysis = await latest_for_session(session_id)
    if analysis is None:
        raise ValueError(f"could not analyze session {session_id}")

    session = await get_session(session_id)
    if session is None:
        raise ValueError(f"unknown session {session_id}")

    timeline = await build_timeline(session_id)
    all_indicators = await list_indicators()
    indicators = [i for i in all_indicators if session_id in i.session_ids]

    created = datetime.now(timezone.utc)
    report = ThreatReport(
        id=str(uuid.uuid4()),
        title=f"{analysis.classification} — {session.attacker_ip}",
        session_id=session_id,
        created_at=created.isoformat().replace("+00:00", "Z"),
        generated_by=analysis.model,
        executive_summary=analysis.behavior_summary,
        incident_overview=IncidentOverview(
            attacker_ip=session.attacker_ip,
            target=session.honeypot_name,
            time_range=f"{session.started_at} — {session.ended_at or 'ongoing'}",
            protocol=session.protocol,
            risk=analysis.risk,
            risk_score=analysis.risk_score,
        ),
        timeline=timeline,
        attacker_behavior=AttackerBehavior(
            classification=analysis.classification,
            explanation=analysis.behavior_summary,
            confidence=analysis.confidence,
        ),
        mitre=analysis.techniques,
        indicators=indicators,
        threat_assessment=ThreatAssessment(
            level=analysis.risk,
            confidence=analysis.confidence,
            narrative=analysis.behavior_summary,
        ),
        recommended_actions=analysis.recommended_actions,
    )

    async with get_session_factory()() as db:
        db.add(
            ReportRow(
                id=uuid.UUID(report.id),
                session_id=session_id,
                analysis_id=uuid.UUID(analysis.id),
                title=report.title,
                created_at=created,
                generated_by=report.generated_by,
                body=report.model_dump(by_alias=True),
            )
        )
        await db.commit()

    return report


async def list_reports() -> list[ThreatReport]:
    async with get_session_factory()() as db:
        rows = (
            (await db.execute(select(ReportRow).order_by(ReportRow.created_at.desc())))
            .scalars()
            .all()
        )
    return [ThreatReport.model_validate(row.body) for row in rows]
