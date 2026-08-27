export type IndicatorType = "ip" | "domain" | "url" | "hash" | "username" | "filename" | "command";

export interface Indicator {
  id: string;
  type: IndicatorType;
  value: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  sessionIds: string[];
  source: "OBSERVED" | "CORRELATED" | "STATIC ANALYSIS" | "AI INFERENCE";
  tags: string[];
}

export interface ThreatIntelSummary {
  indicators: Indicator[];
  countsByType: Record<IndicatorType, number>;
}
