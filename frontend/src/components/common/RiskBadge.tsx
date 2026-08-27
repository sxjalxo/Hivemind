import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
import type { RiskLevel } from "@/types";

const riskBadge = cva(
  "inline-flex items-center gap-1.5 rounded border font-mono text-[10px] font-semibold uppercase tracking-[0.08em] leading-none",
  {
    variants: {
      level: {
        critical: "border-critical/40 bg-critical/15 text-critical",
        high: "border-high/40 bg-high/15 text-high",
        medium: "border-medium/40 bg-medium/15 text-medium",
        low: "border-low/40 bg-low/15 text-low",
        informational: "border-info/40 bg-info/12 text-info",
      },
      size: {
        sm: "px-1.5 py-[3px]",
        md: "px-2 py-1 text-[11px]",
      },
    },
    defaultVariants: { level: "informational", size: "sm" },
  },
);

const RISK_LABEL: Record<RiskLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
};

interface RiskBadgeProps extends VariantProps<typeof riskBadge> {
  level: RiskLevel;
  score?: number;
  withDot?: boolean;
  className?: string;
}

export function RiskBadge({ level, score, size, withDot = true, className }: RiskBadgeProps) {
  return (
    <span className={cn(riskBadge({ level, size }), className)}>
      {withDot ? <span className="size-1.5 rounded-full bg-current" aria-hidden /> : null}
      {RISK_LABEL[level]}
      {score !== undefined ? <span className="opacity-70">{score}</span> : null}
    </span>
  );
}

/** Normalises loosely-typed backend strings onto the RiskLevel union. */
export function asRiskLevel(value: string | undefined): RiskLevel {
  switch (value?.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "informational";
  }
}
