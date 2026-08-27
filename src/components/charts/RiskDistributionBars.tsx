import { asRiskLevel } from "@/components/common";
import { SEVERITY_COLOR } from "./palette";
import { formatNumber } from "@/utils/format";
import { cn } from "@/lib/utils";

export interface RiskBucket {
  level: string;
  value: number;
}

/**
 * Severity distribution. Rendered as labelled horizontal bars rather than a
 * coloured chart legend: severity is a reserved status scale, so every bar
 * carries its name and count and never relies on colour alone.
 */
export function RiskDistributionBars({
  data,
  onSelect,
}: {
  data: RiskBucket[];
  onSelect?: (level: string) => void;
}) {
  const max = data.reduce((peak, bucket) => Math.max(peak, bucket.value), 0);
  const total = data.reduce((sum, bucket) => sum + bucket.value, 0);

  return (
    <ul className="space-y-2.5">
      {data.map((bucket) => {
        const level = asRiskLevel(bucket.level);
        const width = max === 0 ? 0 : (bucket.value / max) * 100;
        const share = total === 0 ? 0 : (bucket.value / total) * 100;
        const interactive = Boolean(onSelect);

        return (
          <li key={bucket.level}>
            <button
              type="button"
              disabled={!interactive}
              onClick={() => onSelect?.(level)}
              className={cn(
                "group block w-full text-left",
                interactive && "cursor-pointer",
                !interactive && "cursor-default",
              )}
            >
              <div className="flex items-baseline justify-between gap-3 pb-1">
                <span className="flex items-center gap-1.5">
                  <span
                    className="size-2 shrink-0 rounded-[2px]"
                    style={{ backgroundColor: SEVERITY_COLOR[level] }}
                    aria-hidden
                  />
                  <span className="text-xs text-foreground/85">{bucket.level}</span>
                </span>
                <span className="flex items-baseline gap-2">
                  <span className="font-mono text-xs font-semibold tabular-nums text-foreground">
                    {formatNumber(bucket.value)}
                  </span>
                  <span className="w-10 text-right font-mono text-[11px] tabular-nums text-muted-foreground">
                    {share.toFixed(1)}%
                  </span>
                </span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted/60">
                <div
                  className="h-full rounded-full transition-[width] duration-500 group-hover:brightness-110"
                  style={{ width: `${width}%`, backgroundColor: SEVERITY_COLOR[level] }}
                />
              </div>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

/** Ranked command frequency, used for the "Top Commands" panel. */
export function CommandFrequencyBars({
  data,
  onSelect,
}: {
  data: { command: string; count: number; techniqueId?: string }[];
  onSelect?: (command: string) => void;
}) {
  const max = data.reduce((peak, row) => Math.max(peak, row.count), 0);

  return (
    <ul className="space-y-2">
      {data.map((row) => {
        const width = max === 0 ? 0 : (row.count / max) * 100;
        return (
          <li key={row.command}>
            <button
              type="button"
              onClick={() => onSelect?.(row.command)}
              disabled={!onSelect}
              className="group block w-full text-left"
            >
              <div className="flex items-baseline justify-between gap-3 pb-1">
                <span className="min-w-0 truncate font-mono text-xs text-foreground/90">
                  {row.command}
                </span>
                <span className="flex shrink-0 items-baseline gap-2">
                  {row.techniqueId ? (
                    <span className="font-mono text-[10px] text-primary">{row.techniqueId}</span>
                  ) : null}
                  <span className="font-mono text-xs font-semibold tabular-nums text-foreground">
                    {formatNumber(row.count)}
                  </span>
                </span>
              </div>
              <div className="h-1 w-full overflow-hidden rounded-full bg-muted/60">
                <div
                  className="h-full rounded-full bg-primary/70 transition-[width] duration-500 group-hover:bg-primary"
                  style={{ width: `${width}%` }}
                />
              </div>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
