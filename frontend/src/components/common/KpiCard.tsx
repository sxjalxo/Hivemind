import { Minus, TrendingDown, TrendingUp } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatNumber } from "@/utils/format";
import type { DashboardKpi } from "@/services/provider";

const TONE_ACCENT: Record<DashboardKpi["tone"], string> = {
  default: "text-foreground",
  critical: "text-critical",
  high: "text-high",
  info: "text-info",
  ai: "text-ai",
};

const TONE_RAIL: Record<DashboardKpi["tone"], string> = {
  default: "bg-border-strong",
  critical: "bg-critical",
  high: "bg-high",
  info: "bg-info",
  ai: "bg-ai",
};

export function TrendIndicator({
  direction,
  changePct,
  window: windowLabel,
  invert = false,
}: {
  direction: "up" | "down" | "flat";
  changePct: number;
  window?: string;
  /** For metrics where "up" is bad (attacks, alerts) the colour is inverted. */
  invert?: boolean;
}) {
  const Icon = direction === "up" ? TrendingUp : direction === "down" ? TrendingDown : Minus;
  const good = direction === "flat" ? null : invert ? direction === "down" : direction === "up";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 font-mono text-[11px] tabular-nums",
        good === null && "text-muted-foreground",
        good === true && "text-success",
        good === false && "text-high",
      )}
    >
      <Icon className="size-3" aria-hidden />
      {changePct > 0 ? "+" : ""}
      {changePct.toFixed(1)}%
      {windowLabel ? <span className="text-muted-foreground">{windowLabel}</span> : null}
    </span>
  );
}

export function KpiCard({
  kpi,
  onClick,
  className,
}: {
  kpi: DashboardKpi;
  onClick?: () => void;
  className?: string;
}) {
  const interactive = Boolean(onClick);
  const Wrapper = interactive ? "button" : "div";

  return (
    <Wrapper
      {...(interactive ? { type: "button" as const, onClick } : {})}
      className={cn(
        "panel relative overflow-hidden px-4 py-3.5 text-left transition-colors",
        interactive && "hover:border-border-strong hover:bg-accent/30",
        className,
      )}
    >
      <span className={cn("absolute inset-y-0 left-0 w-[2px]", TONE_RAIL[kpi.tone])} aria-hidden />
      <p className="label-caps min-h-[26px] leading-[1.25]">{kpi.label}</p>
      <p
        className={cn(
          "mt-2 font-mono text-2xl font-semibold tabular-nums leading-none",
          TONE_ACCENT[kpi.tone],
        )}
      >
        {formatNumber(kpi.value)}
      </p>
      <div className="mt-2.5">
        <TrendIndicator
          direction={kpi.trendDirection}
          changePct={kpi.trendPct}
          invert={kpi.tone === "critical" || kpi.tone === "high"}
        />
      </div>
    </Wrapper>
  );
}

export function KpiCardSkeleton() {
  return (
    <div className="panel h-[104px] animate-pulse px-4 py-3.5">
      <div className="h-2.5 w-20 rounded bg-muted" />
      <div className="mt-3 h-6 w-16 rounded bg-muted" />
      <div className="mt-3 h-2.5 w-12 rounded bg-muted" />
    </div>
  );
}
