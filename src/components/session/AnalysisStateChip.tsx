import { Bot, CircleDashed, CircleCheck, CircleX, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import type { AnalysisState } from "@/types";

const STATE: Record<
  AnalysisState,
  { label: string; className: string; icon: typeof Bot; spin?: boolean }
> = {
  not_analyzed: {
    label: "Not analysed",
    className: "border-border bg-muted/40 text-muted-foreground",
    icon: CircleDashed,
  },
  queued: {
    label: "Queued",
    className: "border-info/40 bg-info/10 text-info",
    icon: CircleDashed,
  },
  analyzing: {
    label: "Analysing",
    className: "border-ai/40 bg-ai/12 text-ai",
    icon: Loader2,
    spin: true,
  },
  completed: {
    label: "Analysed",
    className: "border-success/40 bg-success/12 text-success",
    icon: CircleCheck,
  },
  failed: {
    label: "Failed",
    className: "border-critical/40 bg-critical/12 text-critical",
    icon: CircleX,
  },
};

export function AnalysisStateChip({
  state,
  className,
}: {
  state: AnalysisState;
  className?: string;
}) {
  const meta = STATE[state];
  const { icon: Icon } = meta;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-1.5 py-[3px] font-mono text-[10px] font-semibold uppercase tracking-[0.06em] leading-none",
        meta.className,
        className,
      )}
    >
      <Icon className={cn("size-3", meta.spin && "animate-spin")} aria-hidden />
      {meta.label}
    </span>
  );
}
