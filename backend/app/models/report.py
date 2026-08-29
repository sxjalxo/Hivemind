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
    level: str
    confidence: float
    narrative: str


class ThreatReport(CamelModel):
    id: str
    title: str
    session_id: str
    created_at: str
    generated_by: str
    executive_summary: str
    incident_overview: IncidentOverview
    timeline: list[SessionTimelineEvent]
    attacker_behavior: AttackerBehavior
    mitre: list[TechniqueMappingOut]
    indicators: list[Indicator]
    threat_assessment: ThreatAssessment
    recommended_actions: list[RecommendedActionOut]
