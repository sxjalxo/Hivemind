from app.models.analysis import EvidenceRefOut
from app.serialization import CamelModel


class MitreTechniqueOut(CamelModel):
    id: str
    name: str
    tactic: str
    observed: bool
    session_count: int
    confidence: float | None = None
    evidence: list[EvidenceRefOut]
    related_commands: list[str]
    ai_explanation: str | None = None
    last_seen: str | None = None


class MitreCoverage(CamelModel):
    techniques: list[MitreTechniqueOut]
    observed_count: int
    total_count: int
