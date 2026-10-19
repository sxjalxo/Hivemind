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


# `classification` is a closed vocabulary, not free text (2026-10-19). Free text
# gave 22 different labels to 134 live sessions that ran near-identical
# commands -- the same busybox loader called a dropper in one session and
# reconnaissance in the next -- so the label could not be counted, filtered or
# compared. `OllamaClient.complete_json` sends this model's JSON schema as the
# `format`, so the enum is enforced while the model generates; anything else
# that builds a ClassificationResult is validated against it, and a refusal
# degrades to the visible "Unclassified" fallback in `_classify_one`.
#
# The closed set also retires the old length bound: the value is stored, shown,
# used as a report title, re-rendered into the recommend prompt and indexed as
# the keyword `ai_classification`, and now it can only ever be one of these.
# The definitions the model sees are in prompts/classify.md -- keep them in step.
Classification = Literal[
    "Credential brute force",
    "Reconnaissance",
    "Botnet loader",
    "Malware dropper",
    "Cryptominer deployment",
    "Persistence",
    "Credential access",
    "Defense evasion",
    "Unclassified",
]
#
# `behavior_summary` is deliberately NOT bounded: `_merge_classifications`
# concatenates one summary per chunk into a new ClassificationResult, so any
# per-call bound would be breached by the merge itself -- a ValidationError in
# our own code that would abort a completed analysis rather than degrade it.


class ClassificationResult(BaseModel):
    classification: Classification
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
