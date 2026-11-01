from app.models.analysis import RecommendedActionOut, TechniqueMappingOut
from app.models.intel import Indicator
from app.models.session import SessionTimelineEvent
from app.serialization import CamelModel


class IncidentOverview(CamelModel):
    attacker_ip: str
    target: str
    time_range: str
    protocol: str
    risk: str
    risk_score: int


class AttackerBehavior(CamelModel):
    classification: str
    explanation: str
    confidence: float


class ThreatAssessment(CamelModel):
    # Stored snapshots written before 2026-11-01 also carry `narrative` (the
    # model's behaviour summary a third time); it is ignored on read.
    level: str
    confidence: float


class ThreatReport(CamelModel):
    id: str
    title: str
    session_id: str
    created_at: str
    generated_by: str
    executive_summary: str
    # True when the summary is built from recorded facts. Snapshots written
    # before 2026-11-01 hold the model's behaviour summary here; the default
    # keeps them labelled as inference, never as observed.
    executive_summary_observed: bool = False
    incident_overview: IncidentOverview
    timeline: list[SessionTimelineEvent]
    attacker_behavior: AttackerBehavior
    mitre: list[TechniqueMappingOut]
    indicators: list[Indicator]
    threat_assessment: ThreatAssessment
    recommended_actions: list[RecommendedActionOut]
