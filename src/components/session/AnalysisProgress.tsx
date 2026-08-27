import { Check, Loader2 } from "lucide-react";
import { ANALYSIS_STAGES } from "@/services/analysis";
import { cn } from "@/lib/utils";

/**
 * Stage list for a running analysis. The stages describe the backend pipeline;
 * the UI reflects progress, it does not simulate the model.
 */
export function AnalysisProgress({
  activeIndex,
  className,
}: {
  /** Index into ANALYSIS_STAGES; equal to the length once finished. */
  activeIndex: number;
  className?: string;
}) {
  return (
    <ol className={cn("space-y-1.5", className)}>
      {ANALYSIS_STAGES.map((stage, index) => {
        const done = index < activeIndex;
        const active = index === activeIndex;

        return (
          <li key={stage.stage} className="flex items-center gap-2.5">
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
              {stage.label}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
