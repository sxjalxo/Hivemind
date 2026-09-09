import {
  EVALUATOR_STATUS_LABELS,
  RUN_STATUS_HINTS,
  RUN_STATUS_LABELS,
} from "@/services/evaluation";
import { cn } from "@/lib/utils";
import type { EvaluationRunStatus, EvaluatorStatus } from "@/types";

/**
 * A run's status.
 *
 * `failed` means OUR orchestration failed. A run can be `failed` with every
 * module `completed` — the modules measured what they measured and those
 * measurements stand. It is never relabelled as the honeypot failing.
 */
export function RunStatusChip({
  status,
  className,
}: {
  status: EvaluationRunStatus;
  className?: string;
}) {
  return (
    <span
      title={RUN_STATUS_HINTS[status]}
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-[3px] font-mono text-[10px] font-semibold uppercase tracking-[0.06em] leading-none",
        status === "completed" && "border-success/40 bg-success/12 text-success",
        status === "running" && "border-info/40 bg-info/12 text-info",
        status === "queued" && "border-border bg-muted/40 text-muted-foreground",
        status === "failed" && "border-high/40 bg-high/12 text-high",
        className,
      )}
    >
      {RUN_STATUS_LABELS[status]}
    </span>
  );
}

/**
 * Whether the LLM evaluator ran. Anything but `completed` means every
 * `evaluatorRating` on the run is null — an absent assessment, never a zero.
 */
export function EvaluatorStatusChip({
  status,
  model,
  className,
}: {
  status: EvaluatorStatus;
  model: string | null;
  className?: string;
}) {
  return (
    <span
      title={
        status === "completed"
          ? `The evaluator ran${model ? ` on ${model}` : ""}.`
          : "Every evaluator rating on this run is null. That is an absent assessment, not a score of zero."
      }
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-[3px] font-mono text-[10px] font-semibold uppercase tracking-[0.06em] leading-none",
        status === "completed"
          ? "border-ai/40 bg-ai/12 text-ai"
          : "border-border bg-muted/40 text-muted-foreground",
        className,
      )}
    >
      {EVALUATOR_STATUS_LABELS[status]}
    </span>
  );
}
