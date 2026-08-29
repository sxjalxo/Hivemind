from app.serialization import CamelModel

ANALYSIS_STAGES = [
    "parsing_logs",
    "identifying_patterns",
    "classifying_behavior",
    "extracting_indicators",
    "mapping_mitre",
    "generating_intel",
    "generating_recommendations",
]

STAGE_LABELS = {
    "parsing_logs": "Parsing logs",
    "identifying_patterns": "Identifying patterns",
    "classifying_behavior": "Classifying behaviour",
    "extracting_indicators": "Extracting indicators",
    "mapping_mitre": "Mapping ATT&CK",
    "generating_intel": "Generating intelligence",
    "generating_recommendations": "Generating recommendations",
}


class EvidenceRefOut(CamelModel):
    artifact: str
    session_id: str
    timestamp: str
    event_id: str


class TechniqueMappingOut(CamelModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: list[EvidenceRefOut]
    related_commands: list[str]
    ai_explanation: str | None
    timestamp: str


class LabelledEvidence(CamelModel):
    label: str
    evidence: list[EvidenceRefOut]


class SeverityEvidence(CamelModel):
    label: str
    severity: str
    evidence: list[EvidenceRefOut]


class RecommendedActionOut(CamelModel):
    priority: str
    action: str
    rationale: str


class SessionAnalysis(CamelModel):
    id: str
    session_id: str
    model: str
    analysis_type: str
    status: str
    created_at: str
    duration_seconds: int
    classification: str
    confidence: float
    risk_score: int
    risk: str
    behavior_summary: str
    observed_behavior: list[LabelledEvidence]
    suspicious_indicators: list[SeverityEvidence]
    recommended_actions: list[RecommendedActionOut]
    techniques: list[TechniqueMappingOut]


class LiveAnalysisMetrics(CamelModel):
    progress_pct: int | None = None
    events_processed: int | None = None
    commands_analyzed: int | None = None
    techniques_detected: int | None = None
    iocs_extracted: int | None = None


class AnalysisProgressEvent(CamelModel):
    stage_index: int
    stage: str
    metrics: LiveAnalysisMetrics | None = None
