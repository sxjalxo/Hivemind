"""Response models for the honeypot-realism evaluation surface.

Two rules govern every number that leaves this module.

`None` means "not established" and must never be rendered as 0. A fact we
could not determine is not evidence against the honeypot, so scoring excludes
`unknown` from both numerator and denominator and returns `None` when nothing
was established (see `app.services.evaluation.scoring`).

`deterministic_score` and `evaluator_rating` answer different questions --
"did the honeypot do the checkable things?" and "would an attacker believe
it?" -- and are never combined. There is deliberately no composite field
anywhere below.
"""

from pydantic import ConfigDict

from app.serialization import CamelModel

# Mirrors ANALYSIS_STAGES in app.models.analysis: a run publishes one progress
# event per stage under `evaluation:<run_id>`. The two lists are deliberately
# separate -- an evaluation's stages are not an analysis's -- but the event
# SHAPE is identical so one WebSocket client can render either.
#
# `resetting` and the two fingerprints are not in this list on purpose: they
# run before the run row exists, so there is no run id to publish under yet.
# A failure there is reported to the caller of `start_run`, not on a channel
# nobody can be subscribed to.
EVALUATION_STAGES = [
    "starting_capture",
    "scanning_services",
    "probing_shell",
    "running_chains",
    "scoring_characteristics",
    "evaluating_realism",
    "persisting_results",
]

STAGE_LABELS = {
    "starting_capture": "Starting packet capture",
    "scanning_services": "Scanning services",
    "probing_shell": "Probing the shell",
    "running_chains": "Running attack chains",
    "scoring_characteristics": "Scoring characteristics",
    "evaluating_realism": "Evaluating realism",
    "persisting_results": "Persisting results",
}


class LiveEvaluationMetrics(CamelModel):
    progress_pct: int | None = None
    probes_executed: int | None = None
    chain_steps_verified: int | None = None
    characteristics_scored: int | None = None
    characteristics_evaluated: int | None = None


# A run dispatched to the background can fail BEFORE its row exists -- the
# reset or either fingerprint aborts, by the deliberate ruling above. That
# exception reaches no HTTP caller, `GET /evaluations/{id}` would 404 with no
# explanation, and a subscriber would wait forever. So the router publishes
# one terminal event under this stage instead: our own failure is reported,
# never hidden. It is the only event that carries `error`, and the only one
# with a negative `stage_index` -- it is not a position in EVALUATION_STAGES.
EVALUATION_FAILED_STAGE = "failed"
EVALUATION_FAILED_STAGE_INDEX = -1


class EvaluationProgressEvent(CamelModel):
    """Same shape as AnalysisProgressEvent, different stage vocabulary.

    `stage == EVALUATION_FAILED_STAGE` is terminal: the run never started and
    nothing will follow on this channel. Every other event is a stage the run
    entered, and `error` is None on all of them.
    """

    stage_index: int
    stage: str
    metrics: LiveEvaluationMetrics | None = None
    error: str | None = None


class CategoryScoreOut(CamelModel):
    characteristic: str
    # None means "not established" and must never be rendered as 0. These two
    # answer different questions and are never combined.
    deterministic_score: float | None = None
    evaluator_rating: float | None = None
    # Why `evaluator_rating` is what it is, for THIS characteristic. The run's
    # own `evaluator_status` is an aggregate and cannot answer it. Defaults
    # to "unrecorded" so a row written before the column reads as a gap in
    # the record rather than as a claim.
    evaluator_status: str = "unrecorded"
    evaluator_detail: str | None = None


class ModuleResultOut(CamelModel):
    module: str
    module_status: str
    detail: str | None = None


class EvidenceOut(CamelModel):
    kind: str
    es_event_id: str | None = None
    chain_step_id: str | None = None
    probe_result_id: str | None = None


class FindingOut(CamelModel):
    id: str
    characteristic: str
    severity: str
    finding: str
    recommendation: str | None = None
    source: str
    # Identity across runs. The id changes every run; this does not, and it is
    # what lets a client line one run's findings up against another's.
    finding_key: str
    evidence: list[EvidenceOut]


class FindingLifecycleOut(CamelModel):
    """One defect, and what happened to it between two runs.

    `status` is five-valued, not four. `undetermined` exists because absence
    of a finding has two causes -- the fact came back `observed`, or the fact
    was never established -- and reporting the second as `fixed` would
    manufacture good news out of an infrastructure failure.

    `attributable` carries the same honesty the score delta already does: when
    the evaluation configuration moved between the two runs, a defect that
    vanished may mean WE STOPPED ASKING rather than that it was repaired. The
    entry is still reported; it is simply marked.

    `is_slot` marks an evaluator entry. There is one evaluator verdict per
    characteristic per run, so its key always matches itself: `persisting`
    means the evaluator still had something to say about that characteristic,
    NOT that the same flaw is still there. Clients must render it as a slot.

    `from_run_id` says which run the text and evidence were read from. For
    `fixed` there is no row in head at all, so they come from base.
    """

    key: str
    status: str
    attributable: bool
    is_slot: bool
    from_run_id: str
    characteristic: str | None = None
    severity: str | None = None
    source: str | None = None
    finding: str | None = None
    recommendation: str | None = None
    evidence: list[EvidenceOut] = []


class ChainStepOut(CamelModel):
    # `EvaluationEvidence.chain_step_id` points at this row, so a finding that
    # cites a chain step is only groundable if the id crosses the API too.
    # Without it the UI receives a citation it cannot resolve to anything.
    id: str
    chain_id: str
    step_index: int
    command: str
    cowrie_event_id: str | None = None
    matched_rule_id: str | None = None
    expected_technique_id: str
    fact_status: str


class ProbeResultOut(CamelModel):
    id: str
    module: str
    probe_id: str
    target: str
    establishes: str | None = None
    value: str | None = None
    fact_status: str


class EvaluationRunOut(CamelModel):
    id: str
    honeypot_id: str
    status: str
    started_at: str
    finished_at: str | None = None
    agent_model: str
    evaluator_model: str | None = None
    evaluator_status: str
    honeypot_fingerprint: str
    evaluation_config_fingerprint: str
    # Who started this run: `user:<clerk_id>`, `unauthenticated` (no identity
    # existed to record) or `unrecorded` (the run predates the audit trail).
    # Three distinct values on purpose -- see `db.models.EvaluationRun`.
    started_by: str = "unrecorded"
    # The actor's email as the token asserted it at the time. A label for a
    # human reading the history, never the identity.
    started_by_label: str | None = None
    category_scores: list[CategoryScoreOut]
    modules: list[ModuleResultOut]
    findings: list[FindingOut]
    chain_steps: list[ChainStepOut]
    probe_results: list[ProbeResultOut]


class StartEvaluationRequest(CamelModel):
    """The entire request body for starting a run: one honeypot id.

    CONTAINMENT. There is deliberately no host, port, address, target,
    command or timeout field here, and `extra="forbid"` means one cannot be
    smuggled in either. The target is resolved from the honeypot registry to
    a fixed compose service name in settings (see
    `app.services.evaluation.runs.start_run`), so there is no code path from
    an HTTP request to an arbitrary host. Adding a field to this model widens
    the attack surface and is asserted against in
    `tests/test_evaluation_api.py`.
    """

    model_config = ConfigDict(extra="forbid")

    honeypot_id: str


class StartEvaluationResponse(CamelModel):
    """202 Accepted. The run is dispatched, not finished.

    The id is allocated by the router precisely so the client has the
    progress channel's key before the run publishes anything. `JobQueue`
    has no replay, so events between this response and the client's
    subscription are lost -- `GET /api/evaluations/{run_id}` is the
    authoritative record, the channel is only the live view.
    """

    run_id: str


class EvaluationRunSummary(CamelModel):
    """One history row: enough to render a list and a trend, and no more.

    `EvaluationRunOut` carries every probe result, finding, evidence row and
    chain step, hydrated with ~7 queries per run -- returning a list of those
    would transfer the whole evaluation database to draw a table. The
    category scores are here because a trend line needs them; everything
    per-run-detail stays behind `GET /api/evaluations/{run_id}`.

    `deterministic_score` and `evaluator_rating` travel side by side, never
    combined, and None still means "not established".
    """

    id: str
    honeypot_id: str
    status: str
    started_at: str
    finished_at: str | None = None
    agent_model: str
    evaluator_model: str | None = None
    evaluator_status: str
    honeypot_fingerprint: str
    evaluation_config_fingerprint: str
    # Who started this run: `user:<clerk_id>`, `unauthenticated` (no identity
    # existed to record) or `unrecorded` (the run predates the audit trail).
    # Three distinct values on purpose -- see `db.models.EvaluationRun`.
    started_by: str = "unrecorded"
    # The actor's email as the token asserted it at the time. A label for a
    # human reading the history, never the identity.
    started_by_label: str | None = None
    category_scores: list[CategoryScoreOut]


class RunComparison(CamelModel):
    """A delta between two runs, with its attribution stated plainly.

    `classification` is `same_configuration` only when BOTH fingerprints
    match; otherwise `configuration_changed`. The comparison is never
    refused -- refusing hides the delta without explaining it.

    `differences` names exactly which fingerprint(s) moved, because the two
    carry OPPOSITE implications and a single classification cannot express
    both:

      * `honeypot_fingerprint` changed -- this is the POINT of a comparison.
        The honeypot was rebuilt or its cowrie.cfg edited, and that change is
        the improvement being measured. The delta is attributable to it.
      * `evaluation_config_fingerprint` changed -- OUR probes, chains,
        rulebook or agent budget moved. The two runs asked the honeypot
        different questions, so the delta is NOT attributable to the
        honeypot at all.

    Known residual gap (documented in `evaluation.fingerprints`): the scoring
    and compaction ALGORITHMS are not fingerprinted. `scoring.py` holds no
    constants to hash, so two runs across an edit to how a fraction is
    computed fingerprint identically -- compare those by git revision. The
    target, the nmap timeout, the capture interface and the result-deciding
    constants in `rules.py`, `static/nmap.py` and `agent.py` ARE covered.
    """

    base: EvaluationRunOut
    head: EvaluationRunOut
    # same_configuration | configuration_changed. Never refuse the
    # comparison; say plainly why a delta may not be attributable.
    classification: str
    differences: list[str]
    # characteristic -> head.deterministic_score - base.deterministic_score.
    # None wherever either side is None: a delta against "not established" is
    # not a delta, and computing one would resurrect the 0.0 that `None`
    # exists to prevent. `evaluator_rating` is deliberately not deltaed here
    # and never merged with these values.
    deltas: dict[str, float | None]
    # Per-defect lifecycle across the same pair, ordered worst news first:
    # regressed, new, persisting, undetermined, fixed. Empty when neither run
    # has a finding either side can identify.
    findings: list[FindingLifecycleOut] = []
