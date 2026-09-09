import { queryOptions } from "@tanstack/react-query";
import { provider } from "./index";
import { ApiError } from "./api";
import {
  EVALUATION_STAGES,
  type EvaluationCategoryScore,
  type EvaluationCharacteristic,
  type EvaluationFindingSeverity,
  type EvaluationModuleStatus,
  type EvaluationRun,
  type EvaluationRunStatus,
  type EvaluationStage,
  type EvaluatorStatus,
  type RiskLevel,
} from "@/types";

/**
 * Query options and presentation vocabulary for the evaluation surface.
 *
 * Helpers live here rather than beside a component so route and component
 * files export components only.
 *
 * ONE SCALE. The API reports every score as a 0-1 fraction and the house
 * convention for a 0-1 value is `ConfidenceBar`, which renders it as a
 * percentage. Everything below therefore speaks in percent, and
 * `SCORE_SCALE_NOTE` is printed wherever scores are shown so a reader can
 * never mistake which scale they are looking at. There is no 0-10 scale
 * anywhere in this system.
 */

/** Printed next to every score so the scale is stated, not inferred. */
export const SCORE_SCALE_NOTE =
  "Scores are 0-1 as reported by the API, shown as percentages (0.86 → 86%).";

/** The two assessments are never combined; this says so wherever they meet. */
export const NO_COMPOSITE_NOTE =
  "Deterministic and evaluator assessments answer different questions and are never combined. There is no overall score.";

/** Rendered wherever a null score would otherwise be mistaken for a zero. */
export const NOT_ESTABLISHED = "not established";

/** Rendered where a characteristic is absent from a run's categoryScores. */
export const NOT_MEASURED = "not measured";

export const EVALUATION_STAGE_LABELS: Record<EvaluationStage, string> = {
  starting_capture: "Starting packet capture",
  scanning_services: "Scanning services",
  probing_shell: "Probing the shell",
  running_chains: "Running attack chains",
  scoring_characteristics: "Scoring characteristics",
  evaluating_realism: "Evaluating realism",
  persisting_results: "Persisting results",
};

/** Every characteristic the backend can score, in a stable display order. */
export const EVALUATION_CHARACTERISTICS: EvaluationCharacteristic[] = [
  "basic_commands",
  "file_system",
  "services",
  "attack_possibilities",
  "sanity",
  "context",
];

export const CHARACTERISTIC_LABELS: Record<EvaluationCharacteristic, string> = {
  basic_commands: "Basic commands",
  file_system: "File system",
  services: "Services",
  attack_possibilities: "Attack possibilities",
  sanity: "Sanity",
  context: "Context",
};

export const CHARACTERISTIC_SHORT_LABELS: Record<EvaluationCharacteristic, string> = {
  basic_commands: "Commands",
  file_system: "Files",
  services: "Services",
  attack_possibilities: "Attacks",
  sanity: "Sanity",
  context: "Context",
};

export const RUN_STATUS_LABELS: Record<EvaluationRunStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
};

/**
 * `failed` is OUR orchestration failing, not the honeypot failing -- a run can
 * be `failed` with every module `completed`. Never relabel it.
 */
export const RUN_STATUS_HINTS: Record<EvaluationRunStatus, string> = {
  queued: "Accepted but not yet started.",
  running: "The run is in progress.",
  completed: "The orchestration finished and persisted its results.",
  failed:
    "OUR orchestration failed. Modules that completed before the failure kept the measurements they made; this is not a verdict on the honeypot.",
};

export const EVALUATOR_STATUS_LABELS: Record<EvaluatorStatus, string> = {
  completed: "Evaluator completed",
  unavailable: "Evaluator unavailable",
  evaluator_failed: "Evaluator failed",
};

/**
 * What to render in place of an evaluator rating. Never a zero: a missing
 * evaluator is a gap in what we could measure, not a verdict.
 */
export const EVALUATOR_ABSENCE_TEXT: Record<Exclude<EvaluatorStatus, "completed">, string> = {
  unavailable: "Evaluator assessment unavailable — no cloud model configured",
  evaluator_failed: "Evaluator assessment failed — the cloud model returned no usable rating",
};

export const MODULE_STATUS_LABELS: Record<EvaluationModuleStatus, string> = {
  completed: "Completed",
  timeout: "Timed out",
  error: "Error",
  budget_exceeded: "Budget exceeded",
  skipped: "Skipped",
};

/** A module that did not complete leaves facts unknown, not negative. */
export const MODULE_STATUS_HINTS: Record<EvaluationModuleStatus, string> = {
  completed: "The module ran to completion.",
  timeout: "The module stopped early; the facts it had not reached are unknown, not failed.",
  error: "The module errored; the facts it had not reached are unknown, not failed.",
  budget_exceeded: "The module hit its budget; unreached facts are unknown, not failed.",
  skipped: "The module never ran, so it established nothing either way.",
};

/** Finding severities are already a subset of RiskLevel, so RiskBadge takes them. */
export const SEVERITY_AS_RISK: Record<EvaluationFindingSeverity, RiskLevel> = {
  high: "high",
  medium: "medium",
  low: "low",
};

/** A 0-1 score as a percentage string, or null when nothing was established. */
export function formatScorePct(score: number | null): string | null {
  if (score === null) return null;
  return `${Math.round(Math.max(0, Math.min(1, score)) * 100)}%`;
}

/**
 * A delta of two 0-1 scores, expressed in percentage points so it is never
 * confused with a score. Null in, null out -- a delta against "not
 * established" is not a delta, and must never render as 0.
 */
export function formatDeltaPp(delta: number | null): string | null {
  if (delta === null) return null;
  const points = Math.round(delta * 100);
  return `${points > 0 ? "+" : points < 0 ? "−" : "±"}${Math.abs(points)} pp`;
}

/** Fingerprints are `sha256:` + 64 hex characters: opaque and far too long. */
export function shortFingerprint(fingerprint: string): string {
  const [algorithm, digest] = fingerprint.split(":", 2);
  if (digest === undefined) return fingerprint.slice(0, 14);
  return `${algorithm}:${digest.slice(0, 12)}`;
}

/**
 * A run's score for one characteristic, or undefined when the run did not
 * measure it at all. `undefined` (not measured) and a present-but-null score
 * (not established) are different absences and are rendered differently.
 *
 * Takes a plain string so a characteristic the backend adds later is still
 * looked up rather than cast away.
 */
export function findScore(
  run: { categoryScores: EvaluationCategoryScore[] },
  characteristic: string,
): EvaluationCategoryScore | undefined {
  return run.categoryScores.find((score) => score.characteristic === characteristic);
}

/** A display label for a characteristic key, including one we do not know. */
export function characteristicLabel(characteristic: string): string {
  return (
    CHARACTERISTIC_LABELS[characteristic as EvaluationCharacteristic] ??
    characteristic.replace(/_/g, " ")
  );
}

/** A run stops moving once it is completed or failed. */
export function isSettledRun(run: EvaluationRun): boolean {
  return run.status === "completed" || run.status === "failed";
}

/** Cadence of the authoritative GET while a run is in flight. */
export const EVALUATION_POLL_MS = 2_000;

/**
 * How long a dispatched run may go without a record before we call it dead.
 *
 * A run that fails before its row exists 404s PERMANENTLY, so an unbounded
 * "still starting" wait spins forever. The terminal progress frame usually
 * says why first; this bound is what covers the case where even that frame was
 * missed (the channel has no replay).
 */
export const EVALUATION_RECORD_GRACE_MS = 45_000;

/**
 * The authoritative record of a run, or null when no row exists for the id.
 *
 * A 404 is NOT always "not yet started": if the run aborted before its row was
 * inserted this 404s forever. Null is returned rather than thrown so a caller
 * can bound its own wait instead of retrying an error indefinitely.
 */
export async function loadEvaluationOrNull(id: string): Promise<EvaluationRun | null> {
  try {
    return await provider.getEvaluation(id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

export const evaluationQueries = {
  list: (limit?: number) =>
    queryOptions({
      queryKey: ["evaluations", limit ?? null],
      queryFn: () => provider.listEvaluations(limit),
    }),
  /** Resolves to null when the id has no run row. See loadEvaluationOrNull. */
  detail: (id: string) =>
    queryOptions({
      queryKey: ["evaluation", id],
      queryFn: () => loadEvaluationOrNull(id),
    }),
  compare: (base: string, head: string) =>
    queryOptions({
      queryKey: ["evaluation-compare", base, head],
      queryFn: () => provider.compareEvaluations(base, head),
    }),
};

/** Total stages a run publishes, for progress copy. */
export const EVALUATION_STAGE_COUNT = EVALUATION_STAGES.length;
