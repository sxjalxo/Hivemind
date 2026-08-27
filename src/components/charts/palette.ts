import type { RiskLevel } from "@/types";

/**
 * Chart colour assignments.
 *
 * Every value here is a design-token reference, and the underlying tokens were
 * checked with the dataviz palette validator against the panel surface. Colour
 * is assigned to an *entity* (a tactic, a severity), never to a rank, so a
 * filter that removes series never repaints the ones that remain.
 */

export const SERIES = {
  events: "var(--color-series-1)",
  highRisk: "var(--color-series-2)",
} as const;

/** Severity is a reserved status scale — never reused as a generic series colour. */
export const SEVERITY_COLOR: Record<RiskLevel, string> = {
  critical: "var(--color-critical)",
  high: "var(--color-high)",
  medium: "var(--color-medium)",
  low: "var(--color-low)",
  informational: "var(--color-info)",
};

const TACTIC_SLOTS = [
  "var(--color-tactic-1)",
  "var(--color-tactic-2)",
  "var(--color-tactic-3)",
  "var(--color-tactic-4)",
  "var(--color-tactic-5)",
  "var(--color-tactic-6)",
  "var(--color-tactic-7)",
] as const;

export const OTHER_COLOR = "var(--color-tactic-other)";

/**
 * Permanent tactic -> hue map. Only seven hues survive CVD validation, so the
 * remaining tactics share the neutral "Other" slot and are always enumerated by
 * name and count in the legend rather than being hidden.
 */
export const TACTIC_COLOR: Record<string, string> = {
  Reconnaissance: TACTIC_SLOTS[0],
  Discovery: TACTIC_SLOTS[1],
  Execution: TACTIC_SLOTS[2],
  "Credential Access": TACTIC_SLOTS[3],
  "Initial Access": TACTIC_SLOTS[4],
  "Command and Control": TACTIC_SLOTS[5],
  "Defense Evasion": TACTIC_SLOTS[6],
};

export function tacticColor(name: string): string {
  return TACTIC_COLOR[name] ?? OTHER_COLOR;
}

/** Tactics without a dedicated hue, kept visible through the legend. */
export function hasOwnHue(name: string): boolean {
  return name in TACTIC_COLOR;
}

export const AXIS_STYLE = {
  stroke: "var(--color-border)",
  tick: { fill: "var(--color-muted-foreground)", fontSize: 11, fontFamily: "var(--font-mono)" },
} as const;
