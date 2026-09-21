/**
 * Types for the honeypot-realism evaluation surface.
 *
 * Mirrors `backend/app/models/evaluation.py`, which serializes every field as
 * camelCase (`app.serialization.CamelModel`). Two rules govern every number
 * that reaches a component here, and both are load-bearing:
 *
 * `null` means "not established" and must NEVER be rendered as 0. A rendered
 * `0.0` reads as a verdict against the honeypot; a null is a gap in what we
 * could measure. Scoring excludes unknown facts from both numerator and
 * denominator and returns null when nothing was established.
 *
 * `deterministicScore` and `evaluatorRating` answer different questions --
 * "did the honeypot do the checkable things?" and "would an attacker believe
 * it?" -- and are NEVER combined. There is deliberately no composite field
 * anywhere in this file, and no helper that averages the two belongs here.
 */

/**
 * The stages a run publishes on its progress channel, in order.
 *
 * A readonly tuple on purpose: with `noUncheckedIndexedAccess` on, indexing it
 * with an `EvaluationStageIndex` yields an `EvaluationStage` rather than
 * `EvaluationStage | undefined`, so a correctly narrowed consumer needs no
 * defensive `?? "unknown"`.
 *
 * `resetting` and the two fingerprinting steps are deliberately absent: they
 * run before the run row exists, so there is no run id to publish under yet.
 */
export const EVALUATION_STAGES = [
  "starting_capture",
  "scanning_services",
  "probing_shell",
  "running_chains",
  "scoring_characteristics",
  "evaluating_realism",
  "persisting_results",
] as const;

export type EvaluationStage = (typeof EVALUATION_STAGES)[number];

/**
 * A valid position in `EVALUATION_STAGES`.
 *
 * Spelled as literals rather than `number` so that the terminal failure
 * frame's `-1` cannot be passed where a stage index is expected. See
 * `EvaluationFailedProgressEvent`.
 */
export type EvaluationStageIndex = 0 | 1 | 2 | 3 | 4 | 5 | 6;

/** The `stage` of the one terminal frame that is not a stage of the run. */
export const EVALUATION_FAILED_STAGE = "failed";

/**
 * The `stageIndex` of that terminal frame. It is a SENTINEL, not a position:
 * `EVALUATION_STAGES[-1]` is `undefined`, never a stage name.
 */
export const EVALUATION_FAILED_STAGE_INDEX = -1;

/**
 * Live counters attached to a stage frame. Every field is `number | null`
 * because a stage that has not reached a quantity yet reports null for it,
 * and null must not be rendered as 0.
 */
export interface LiveEvaluationMetrics {
  progressPct: number | null;
  probesExecuted: number | null;
  chainStepsVerified: number | null;
  characteristicsScored: number | null;
  characteristicsEvaluated: number | null;
}

/**
 * A frame for a stage the run actually entered.
 *
 * `error` is always null here -- the failure frame is the only event that
 * carries one. `metrics` is typed nullable to match the wire model even though
 * today's only publisher (`runs._emit`) always attaches an object; the null
 * check it forces is the point.
 */
export interface EvaluationStageProgressEvent {
  stageIndex: EvaluationStageIndex;
  stage: EvaluationStage;
  metrics: LiveEvaluationMetrics | null;
  error: null;
}

/**
 * The terminal failure frame, and the whole reason `EvaluationProgressEvent`
 * is a union rather than one interface.
 *
 * A run dispatched to the background can fail BEFORE its row exists -- the
 * container reset or either fingerprint aborts. That exception reaches no HTTP
 * caller, so the router publishes this one frame instead. It carries
 * `stageIndex: -1` AND `metrics: null`, so a consumer that reaches for
 * `EVALUATION_STAGES[stageIndex]` indexes out of range and one that reaches for
 * `metrics.progressPct` throws. Narrow on `stage === EVALUATION_FAILED_STAGE`
 * (or on `error !== null`) before touching either.
 *
 * It is terminal: nothing follows it on the channel, and no run row will ever
 * exist for this id -- `GET /api/evaluations/{runId}` 404s permanently. This
 * frame is the only record of the failure, so surface its `error`.
 *
 * `error` is typed non-null because the single producer (`_publish_start_failure`)
 * always formats one from the exception.
 */
export interface EvaluationFailedProgressEvent {
  stageIndex: typeof EVALUATION_FAILED_STAGE_INDEX;
  stage: typeof EVALUATION_FAILED_STAGE;
  metrics: null;
  error: string;
}

/**
 * One frame from `WS /api/evaluations/{runId}/progress`.
 *
 * THE CHANNEL HAS NO REPLAY AND NO COMPLETION FRAME. Events published between
 * the POST's 202 and the client's subscription are lost, and a client that
 * connects after the run finished receives nothing and waits forever. There is
 * no "already completed" frame and no close on success.
 * `GET /api/evaluations/{runId}` is the authoritative record; this stream is
 * decoration over it. Never gate a completed view on a frame arriving.
 *
 * Subscribe with the exact `runId` string the 202 returned. The route parses
 * the id as a UUID, so a non-UUID id is rejected at the handshake with a 403.
 */
export type EvaluationProgressEvent = EvaluationStageProgressEvent | EvaluationFailedProgressEvent;

/** True for the terminal failure frame, and a type guard for it. */
export function isEvaluationFailure(
  event: EvaluationProgressEvent,
): event is EvaluationFailedProgressEvent {
  return event.stage === EVALUATION_FAILED_STAGE;
}

/**
 * The six characteristics an evaluation scores.
 *
 * `attack_possibilities` is omitted from a run's `categoryScores` entirely when
 * the run executed no chains -- an absent key is "not measured", which is not
 * the same as a present key holding nulls.
 */
export type EvaluationCharacteristic =
  "basic_commands" | "file_system" | "services" | "attack_possibilities" | "sanity" | "context";

/**
 * `queued` is in the database enum and the column permits it, but NOTHING in
 * the backend ever writes it -- a run is inserted as `running`. The UI will not
 * see it today; it is kept in the union so a future writer does not silently
 * break the type.
 *
 * `failed` with every module `completed` is a REAL state: our orchestration
 * failed after the modules measured what they measured. It does not mean the
 * honeypot failed, and the UI must not relabel it as one.
 */
export type EvaluationRunStatus = "queued" | "running" | "completed" | "failed";

/**
 * Whether the LLM evaluator ran. `unavailable` and `evaluator_failed` both mean
 * every `evaluatorRating` on the run is null -- render the absence, not a 0.
 */
export type EvaluatorStatus = "completed" | "unavailable" | "evaluator_failed";

/**
 * Distinct from a fact's own status: a module that timed out leaves its facts
 * unknown, and those must not be read as negative evidence.
 */
export type EvaluationModuleStatus =
  "completed" | "timeout" | "error" | "budget_exceeded" | "skipped";

/** `unknown` is excluded from scoring entirely -- it is not a failed check. */
export type EvaluationFactStatus = "observed" | "not_observed" | "unknown";

export type EvaluationEvidenceKind = "event" | "chain_step" | "probe";

/**
 * The severities the backend actually produces. There is no `FindingSeverity`
 * enum behind this -- `evaluation_findings.severity` is a free string column --
 * so a wider value could appear if a new writer is added. Today only three are
 * ever written: `runs._severity_for` maps an evaluator rating to `high`
 * (< 0.34), `medium` (< 0.67) or `low`, and the deterministic contradiction
 * finding is hard-coded `high`. There is no `critical` and no `info`.
 */
export type EvaluationFindingSeverity = "high" | "medium" | "low";

/**
 * Who raised the finding. `evaluator` is the LLM's judgement of realism;
 * `deterministic` is a contradiction between checkable facts. Like `severity`,
 * the column is a free string with no enum behind it.
 */
export type EvaluationFindingSource = "evaluator" | "deterministic";

/**
 * A citation. Exactly one of the three id fields is set, matching `kind`.
 * `probeResultId` resolves against `EvaluationRun.probeResults` by `id`, and
 * `esEventId` resolves through `DataProvider.getEvent`. `chainStepId` does NOT
 * resolve locally -- see `EvaluationChainStep`. A finding whose evidence cannot
 * be resolved must not be rendered as if it were grounded.
 */
export interface EvaluationEvidence {
  kind: EvaluationEvidenceKind;
  esEventId: string | null;
  chainStepId: string | null;
  probeResultId: string | null;
}

/**
 * The two assessments of one characteristic, side by side and never combined.
 * Either may be null, meaning "not established" -- never 0.
 */
export interface EvaluationCategoryScore {
  characteristic: EvaluationCharacteristic;
  /** 0..1, or null when nothing was established. Never render null as 0. */
  deterministicScore: number | null;
  /** 0..1, or null when the evaluator did not run. Never render null as 0. */
  evaluatorRating: number | null;
}

export interface EvaluationModuleResult {
  module: string;
  moduleStatus: EvaluationModuleStatus;
  detail: string | null;
}

export interface EvaluationFinding {
  id: string;
  characteristic: EvaluationCharacteristic;
  severity: EvaluationFindingSeverity;
  finding: string;
  recommendation: string | null;
  source: EvaluationFindingSource;
  /**
   * Identity ACROSS runs. `id` is new every run; this is not, and it is what
   * lets two runs' findings be lined up against each other.
   */
  findingKey: string;
  evidence: EvaluationEvidence[];
}

/**
 * What happened to one defect between two runs.
 *
 * Five statuses, not four. `undetermined` exists because a finding is absent
 * from a run for two unrelated reasons -- the fact came back `observed`, or
 * the fact was never established -- and rendering the second as `fixed` would
 * show the user good news produced by an infrastructure failure. Never
 * collapse `undetermined` into `fixed`.
 */
export type FindingLifecycleStatus = "new" | "persisting" | "fixed" | "regressed" | "undetermined";

/** One defect's lifecycle entry on `GET /api/evaluations/compare`. */
export interface FindingLifecycle {
  key: string;
  status: FindingLifecycleStatus;
  /**
   * False when the evaluation configuration moved between the two runs. A
   * defect that vanished may then mean WE STOPPED ASKING -- a probe deleted
   * from the probe set makes its finding disappear and look repaired. Render
   * the status, but never as a bare claim about the honeypot.
   */
  attributable: boolean;
  /**
   * An evaluator entry is a SLOT, not a flaw. There is one evaluator verdict
   * per characteristic per run, so its key always matches itself: `persisting`
   * means the evaluator still had something to say about that characteristic,
   * NOT that the same flaw is still there -- the critique may describe an
   * entirely different problem. Label it; do not claim the flaw persists.
   */
  isSlot: boolean;
  /**
   * Which run the text and evidence below were read from. A `fixed` entry has
   * no row in the head run at all, so they come from the base run.
   */
  fromRunId: string;
  characteristic: EvaluationCharacteristic | null;
  severity: EvaluationFindingSeverity | null;
  source: EvaluationFindingSource | null;
  finding: string | null;
  recommendation: string | null;
  evidence: EvaluationEvidence[];
}

/**
 * One step of a replayed attack chain.
 *
 * NOTE: the backend's `ChainStepOut` carries NO `id` field, so a finding's
 * `evidence.chainStepId` (a chain-step row id) cannot be matched against this
 * list -- there is nothing to match it to. Only `probeResultId` resolves
 * locally today. A chain-step citation is best surfaced via `cowrieEventId`
 * through `DataProvider.getEvent`, or shown as unresolvable, never as if it had
 * been resolved.
 */
export interface EvaluationChainStep {
  /**
   * Resolves an `EvaluationEvidence.chainStepId` citation. Without it a
   * chain-step-backed finding would carry a pointer to nothing, which is the
   * one thing the evidence model exists to prevent.
   */
  id: string;
  chainId: string;
  stepIndex: number;
  command: string;
  cowrieEventId: string | null;
  matchedRuleId: string | null;
  expectedTechniqueId: string;
  factStatus: EvaluationFactStatus;
}

/**
 * One deterministic probe and what it established.
 *
 * This list exists so a finding's `evidence.probeResultId` resolves to
 * something. Without it a citation is an unverifiable string, which is exactly
 * the provenance the project refuses to ship.
 */
export interface EvaluationProbeResult {
  id: string;
  module: string;
  probeId: string;
  target: string;
  /** The fact the probe was trying to establish, or null. */
  establishes: string | null;
  /** What it observed, or null when nothing was established. */
  value: string | null;
  factStatus: EvaluationFactStatus;
}

/**
 * One run in full -- `GET /api/evaluations/{runId}`, and the authoritative
 * record of what the run established.
 *
 * A 404 here is NOT always "not yet started". If the run failed before its row
 * existed (the container reset or a fingerprint aborted) it 404s PERMANENTLY,
 * and the only record is the terminal WebSocket frame
 * (`EvaluationFailedProgressEvent`). A UI that reads 404 as "still starting"
 * spins forever. Bound the wait, and treat a received failure frame as final.
 *
 * All timestamps are ISO-8601 strings ending in `Z`.
 */
export interface EvaluationRun {
  id: string;
  honeypotId: string;
  status: EvaluationRunStatus;
  startedAt: string;
  /**
   * Who started the run: `user:<clerk_id>`, `unauthenticated` (no identity
   * existed to record) or `unrecorded` (the run predates the audit trail).
   * Three distinct values deliberately -- a gap in the history is not an
   * anonymous action.
   */
  startedBy: string;
  /** The actor's email as the token asserted it at the time; never the identity. */
  startedByLabel: string | null;
  finishedAt: string | null;
  agentModel: string;
  /** Null when the evaluator never ran. */
  evaluatorModel: string | null;
  evaluatorStatus: EvaluatorStatus;
  /** What the honeypot was: its image and cowrie.cfg. */
  honeypotFingerprint: string;
  /** What we asked it: probes, chains, rulebook, agent budget. */
  evaluationConfigFingerprint: string;
  /** Omits any characteristic the run did not measure. */
  categoryScores: EvaluationCategoryScore[];
  modules: EvaluationModuleResult[];
  findings: EvaluationFinding[];
  chainSteps: EvaluationChainStep[];
  probeResults: EvaluationProbeResult[];
}

/**
 * One history row -- `GET /api/evaluations`. Deliberately NOT an
 * `EvaluationRun`.
 *
 * A full run carries every probe result, finding, evidence row and chain step,
 * hydrated with ~7 queries; a list of those would transfer the whole evaluation
 * database to draw a table. `categoryScores` is here because a trend line needs
 * it. Everything per-run-detail stays behind `GET /api/evaluations/{runId}`, so
 * do not reach for `findings`, `modules`, `chainSteps` or `probeResults` here --
 * they are not sent.
 */
export interface EvaluationRunSummary {
  id: string;
  honeypotId: string;
  status: EvaluationRunStatus;
  startedAt: string;
  /**
   * Who started the run: `user:<clerk_id>`, `unauthenticated` (no identity
   * existed to record) or `unrecorded` (the run predates the audit trail).
   * Three distinct values deliberately -- a gap in the history is not an
   * anonymous action.
   */
  startedBy: string;
  /** The actor's email as the token asserted it at the time; never the identity. */
  startedByLabel: string | null;
  finishedAt: string | null;
  agentModel: string;
  evaluatorModel: string | null;
  evaluatorStatus: EvaluatorStatus;
  honeypotFingerprint: string;
  evaluationConfigFingerprint: string;
  categoryScores: EvaluationCategoryScore[];
}

/**
 * The entire body of `POST /api/evaluations`: one honeypot id.
 *
 * CONTAINMENT. There is deliberately no host, port, address, target, command or
 * timeout field, and the backend model sets `extra="forbid"`, so an unexpected
 * or snake_case key is a 422 rather than a silently ignored one. The target is
 * resolved from the honeypot registry to a fixed compose service name.
 */
export interface StartEvaluationRequest {
  honeypotId: string;
}

/**
 * `POST /api/evaluations` returns `202 Accepted` with ONLY this. The run has
 * not happened yet -- it was dispatched to the background, and there are no
 * scores, findings or modules on this object.
 *
 * The client flow is: POST -> take `runId` -> open
 * `WS /api/evaluations/{runId}/progress` on that exact string -> when the run
 * ends, `GET /api/evaluations/{runId}` for the authoritative record.
 *
 * A `409` from the POST means an evaluation is already running for that
 * honeypot; a `404` means the honeypot id is not in the registry.
 */
export interface StartEvaluationResponse {
  runId: string;
}

/** Whether a delta is attributable to the honeypot at all. */
export type RunComparisonClassification = "same_configuration" | "configuration_changed";

/**
 * A delta between two runs -- `GET /api/evaluations/compare`.
 *
 * `classification` is `same_configuration` only when BOTH fingerprints match.
 * The comparison is never refused; `differences` names which fingerprint(s)
 * moved, because the two carry opposite implications: a changed
 * `honeypotFingerprint` is the point of the comparison, while a changed
 * `evaluationConfigFingerprint` means the two runs asked the honeypot different
 * questions and the delta is not attributable to the honeypot at all.
 */
export interface RunComparison {
  base: EvaluationRun;
  head: EvaluationRun;
  classification: RunComparisonClassification;
  differences: string[];
  /**
   * characteristic -> `head.deterministicScore - base.deterministicScore`.
   * `evaluatorRating` is deliberately never deltaed here and never merged in.
   *
   * A null value is AMBIGUOUS from this payload alone: it means either "not
   * established on one side" or "not measured in this run" (a run with no
   * chains omits `attack_possibilities` entirely). Disambiguate by checking
   * membership in each side's `categoryScores`, and never render a null delta
   * as 0 -- a delta against "not established" is not a delta.
   */
  deltas: Record<string, number | null>;
  /**
   * Per-defect lifecycle across the same pair, ordered worst news first:
   * regressed, new, persisting, undetermined, fixed. Empty when neither run
   * carries a finding either side can identify.
   */
  findings: FindingLifecycle[];
}

/** Default `limit` for `GET /api/evaluations` when the client sends none. */
export const DEFAULT_EVALUATION_LIMIT = 20;

/** Ceiling enforced by the backend: 101 or more is a 422, not a clamp. */
export const MAX_EVALUATION_LIMIT = 100;
