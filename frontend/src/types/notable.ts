/**
 * One item in the notables feed, derived by the backend from stored analyses,
 * rule-backed technique mappings and campaigns. Provenance is the claim's own:
 * a model-rated risk is AI INFERENCE, a rule match is OBSERVED.
 */
export interface Notable {
  /** Stable across requests, so a viewer can tell an item already seen from a new one. */
  id: string;
  kind: "high_risk_session" | "technique_first_seen" | "campaign";
  provenance: "OBSERVED" | "AI INFERENCE" | "CORRELATED";
  title: string;
  detail: string;
  timestamp: string;
  sessionId?: string | null;
  techniqueId?: string | null;
}
