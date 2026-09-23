"""The small types an evaluation run's modules share.

`runs.py` had grown to hold orchestration, hydration, lifecycle and comparison
in one file. Splitting those apart needs somewhere for the few types they all
touch to live, or each new module would import `runs` and `runs` would import
it back.

Nothing here does work. It is deliberately dependency-light -- models, enums
and one formatter -- so that importing it can never pull in the orchestration
it was extracted from.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel

from app.db.models import (
    EvaluationChainStep,
    EvaluationEvidence,
    EvaluationFinding,
    EvaluationModuleResult,
    EvaluationProbeResult,
    EvaluatorStatus,
    ModuleStatus,
)
from app.services.evaluation.static.chains import ChainStepResult


class RunNotFoundError(LookupError):
    """No evaluation run with that id."""


class ChainRun(BaseModel):
    """Chain results plus how the chain stage itself went.

    `_run_chains` may also return a bare `list[ChainStepResult]`; see
    `_as_chain_run`. Two shapes are accepted because the stage has to report
    an ingest timeout (which is OUR failure, not the honeypot's) without
    forcing every caller and stub to construct a wrapper.
    """

    results: list[ChainStepResult] = []
    module_status: str = ModuleStatus.COMPLETED
    detail: str | None = None


@dataclass
class PendingFinding:
    """A finding and the evidence that grounds it, kept together.

    Migration `ad6b0d86d035` installs a CONSTRAINT TRIGGER ... DEFERRABLE
    INITIALLY DEFERRED that rejects any `evaluation_findings` row reaching
    COMMIT with no `evaluation_evidence`. It fires at COMMIT, not at INSERT,
    so a finding and its evidence must be written in ONE transaction. Pairing
    them in one object is what makes "commit a finding, then add evidence"
    unrepresentable.
    """

    finding: EvaluationFinding
    evidence: list[EvaluationEvidence]


@dataclass
class Collected:
    """Everything gathered so far, so a `finally` can persist a partial run."""

    modules: list[EvaluationModuleResult] = field(default_factory=list)
    probe_rows: list[EvaluationProbeResult] = field(default_factory=list)
    chain_rows: list[EvaluationChainStep] = field(default_factory=list)
    scores: dict[str, float | None] = field(default_factory=dict)
    ratings: dict[str, float] = field(default_factory=dict)
    findings: list[PendingFinding] = field(default_factory=list)
    evaluator_status: str = EvaluatorStatus.UNAVAILABLE
    evaluator_model: str | None = None
    # probe row id -> the characteristic it belongs to, so evidence packages
    # can be assembled per characteristic without a second pass over probes.
    characteristic_by_probe_row: dict[uuid.UUID, str] = field(default_factory=dict)
    # characteristic -> (evaluator_status, evaluator_detail). Written for
    # every characteristic the evaluator was asked about, including the ones
    # it could not answer -- that is the whole point. `_persist` fills any
    # characteristic that has a score row but no entry here.
    evaluator_outcomes: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    # Did `_evaluate` actually run? Set at its top, before anything in it can
    # fail. `_finalize`, the findings passes and an `_emit` all execute before
    # it and are all caught, so `_persist` can be reached with the evaluator
    # never having been entered. A characteristic with no recorded outcome
    # then means "the evaluator never ran", NOT "no evidence was gathered for
    # it", and `_resolved_evaluator_outcome` must not state the latter as the
    # reason. A gap in the record is not a positive claim.
    evaluator_ran: bool = False


def iso(moment: datetime) -> str:
    """timezone.utc, `Z`-suffixed. The one timestamp spelling this API emits."""
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
