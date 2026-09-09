import { Check, Loader2 } from "lucide-react";
import { EVALUATION_STAGE_LABELS } from "@/services/evaluation";
import { EVALUATION_STAGES } from "@/types";
import { cn } from "@/lib/utils";

/**
 * Stage list for a running evaluation.
 *
 * `activeIndex` is a position in EVALUATION_STAGES or null. It is NEVER the
 * terminal failure frame's `-1`: that frame is not a stage, it is a report that
 * the run never started, and it is narrowed away by `isEvaluationFailure`
 * before it could reach here. A null index means no frame has arrived, which is
 * different from "at stage 0" -- the channel has no replay, so a run can be
 * well underway with its early frames lost.
 */
export function EvaluationProgress({
  activeIndex,
  className,
}: {
  activeIndex: number | null;
  className?: string;
}) {
  return (
    <ol className={cn("space-y-1.5", className)}>
      {EVALUATION_STAGES.map((stage, index) => {
        const done = activeIndex !== null && index < activeIndex;
        const active = activeIndex !== null && index === activeIndex;

        return (
          <li key={stage} className="flex items-center gap-2.5">
            <span
              className={cn(
                "flex size-5 shrink-0 items-center justify-center rounded-full border",
                done && "border-success/50 bg-success/15 text-success",
                active && "border-ai/50 bg-ai/15 text-ai",
                !done && !active && "border-border bg-muted/30 text-muted-foreground",
              )}
            >
              {done ? (
                <Check className="size-3" aria-hidden />
              ) : active ? (
                <Loader2 className="size-3 animate-spin" aria-hidden />
              ) : (
                <span className="font-mono text-[9px]">{index + 1}</span>
              )}
            </span>
            <span
              className={cn(
                "text-xs",
                done && "text-muted-foreground line-through decoration-border",
                active && "font-medium text-foreground",
                !done && !active && "text-muted-foreground",
              )}
            >
              {EVALUATION_STAGE_LABELS[stage]}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
