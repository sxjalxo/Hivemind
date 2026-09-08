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
    evidence: list[EvidenceOut]


class ChainStepOut(CamelModel):
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

    Known residual gap (documented in `evaluation.fingerprints`): only the
    scoring DATA files are fingerprinted, not the scoring CODE. Two runs
    across an edit to `rules.py`, `compaction.py`, `static/nmap.py` or
    `agent.PER_COMMAND_TIMEOUT_SECONDS` fingerprint identically. So does a
    change of target host/port, the nmap timeout or the tcpdump interface.
    Compare those by git revision, not by this field.
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
