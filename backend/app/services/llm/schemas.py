from typing import Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["critical", "high", "medium", "low", "informational"]
Priority = Literal["P1", "P2", "P3"]


class EvidenceCitation(BaseModel):
    """A pointer to the event that justifies a claim.

    event_id must be one of the ids supplied in the prompt. Task 13 rejects
    any citation naming an id that was not offered.
    """

    event_id: str
    artifact: str


class ClassificationResult(BaseModel):
    classification: str
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: int = Field(ge=0, le=100)
    risk: RiskLevel
    behavior_summary: str
    evidence: list[EvidenceCitation] = Field(min_length=1)


class ObservedBehaviorItem(BaseModel):
    label: str
    evidence: list[EvidenceCitation] = Field(min_length=1)


class SuspiciousIndicatorItem(BaseModel):
    label: str
    severity: RiskLevel
    evidence: list[EvidenceCitation] = Field(min_length=1)


class BehaviorAnalysis(BaseModel):
    observed: list[ObservedBehaviorItem] = Field(default_factory=list)
    suspicious: list[SuspiciousIndicatorItem] = Field(default_factory=list)


class TechniqueProposal(BaseModel):
    technique_id: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)
    ai_explanation: str
    evidence: list[EvidenceCitation] = Field(min_length=1)


class TechniqueProposals(BaseModel):
    techniques: list[TechniqueProposal] = Field(default_factory=list)


class RecommendationItem(BaseModel):
    priority: Priority
    action: str
    rationale: str


class Recommendations(BaseModel):
    actions: list[RecommendationItem] = Field(default_factory=list)
