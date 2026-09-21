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
    # True only when a deterministic rule produced this mapping, matching
    # MitreTechniqueOut.observed. Without it the session view cannot tell an
    # LLM proposal apart from telemetry, which is the one distinction this
    # system exists to preserve.
    #
    # It carries a default because reports are stored as immutable JSONB
    # snapshots and re-validated on read: snapshots written before this field
    # existed have no value for it. False is the safe direction -- it
    # understates provenance on those legacy rows rather than presenting an
    # inference as recorded fact.
    observed: bool = False
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
    # Who ran this: `user:<clerk_id>`, `unauthenticated` (no identity existed
    # to record) or `unrecorded` (predates the audit trail). Three distinct
    # values -- see `db.models.Analysis`.
    started_by: str = "unrecorded"
    started_by_label: str | None = None
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
