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


# Bounds on the free text the model returns, in the spirit of `rating`'s
# range on `EvaluatorVerdict`: a field whose value is stored, re-rendered
# into a later prompt, or indexed has to have a size the caller decided.
#
# `classification` is the one that earns this. The prompt asks for a short
# label ("Automated botnet dropper"), but the model wrote it after reading
# attacker-chosen commands, and the value is then interpolated into the
# recommend prompt, stored, shown, used as a report title, and indexed into
# Elasticsearch as `ai_classification` -- a `keyword` with no `ignore_above`,
# so past Lucene's ~32KB term limit the enrichment write fails and the
# session stays silently un-enriched forever.
#
# Generous enough that a reasonable answer never trips it: over the bound is
# an LLMValidationError, which `_classify_one` degrades to the labelled
# "Unclassified" fallback. Failing to the visible fallback is the right
# direction; quietly storing an unbounded string is not.
#
# `behavior_summary` is deliberately NOT bounded here. `_merge_classifications`
# concatenates one summary per chunk into a new ClassificationResult, so any
# per-call bound would be breached by the merge itself -- as a ValidationError
# in our own code, not an LLMValidationError from a model, so it would abort
# a completed analysis rather than degrade it. It is also never re-rendered
# into another prompt and never indexed as a keyword, which is what makes
# `classification` the field that needs the bound.
_MAX_LABEL_CHARS = 200


class ClassificationResult(BaseModel):
    classification: str = Field(max_length=_MAX_LABEL_CHARS)
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
