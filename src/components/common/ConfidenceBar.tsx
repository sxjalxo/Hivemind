import { cn } from "@/lib/utils";

/**
 * Confidence is always shown numerically alongside the bar — an AI score must
 * never be communicated by colour alone.
 *
 * `value` is a 0-1 fraction, matching how the API reports confidence. Risk
 * scores are the other convention (0-100) and have their own component below.
 */
export function ConfidenceBar({
  value,
  label = "Confidence",
  className,
  compact = false,
}: {
  /** Confidence as a 0-1 fraction, e.g. 0.94. */
  value: number;
  label?: string;
  className?: string | undefined;
  compact?: boolean;
}) {
  const clamped = Math.round(Math.max(0, Math.min(1, value)) * 100);
  const tone = clamped >= 85 ? "bg-success" : clamped >= 60 ? "bg-medium" : "bg-high";

  return (
    <div className={cn("min-w-0", className)}>
      {compact ? null : (
        <div className="mb-1 flex items-baseline justify-between gap-2">
          <span className="label-caps">{label}</span>
          <span className="font-mono text-xs font-semibold tabular-nums text-foreground">
            {clamped}%
          </span>
        </div>
      )}
      <div className="flex items-center gap-2">
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
          <div
            className={cn("h-full rounded-full transition-[width] duration-500", tone)}
            style={{ width: `${clamped}%` }}
          />
        </div>
        {compact ? (
          <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
            {clamped}%
          </span>
        ) : null}
      </div>
    </div>
  );
}

/** Risk score presented as a 0-100 gauge with the number always visible. */
export function RiskScoreMeter({ score, className }: { score: number; className?: string }) {
  const clamped = Math.max(0, Math.min(100, score));
  const tone =
    clamped >= 90
      ? "bg-critical"
      : clamped >= 70
        ? "bg-high"
        : clamped >= 40
          ? "bg-medium"
          : "bg-low";

  return (
    <div className={cn("min-w-[140px]", className)}>
      <div className="flex items-baseline gap-1.5">
        <span className="font-mono text-2xl font-semibold tabular-nums leading-none text-foreground">
          {clamped}
        </span>
        <span className="font-mono text-xs text-muted-foreground">/ 100</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-muted">
        <div className={cn("h-full rounded-full", tone)} style={{ width: `${clamped}%` }} />
      </div>
    </div>
  );
}
