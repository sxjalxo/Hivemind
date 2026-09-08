export type RiskLevel = "critical" | "high" | "medium" | "low" | "informational";

/** Where a displayed fact came from — critical for security UX provenance. */
export type Provenance = "OBSERVED" | "AI INFERENCE" | "CORRELATED" | "STATIC ANALYSIS";

export type DataSourceMode = "demo" | "api";

export interface Trend {
  direction: "up" | "down" | "flat";
  /** Percentage change over the compared window. */
  changePct: number;
  window: string;
}

export interface ServiceStatus {
  id: string;
  name: string;
  state: "connected" | "degraded" | "disconnected" | "running" | "unknown";
  detail?: string | undefined;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export * from "./honeypot";
export * from "./session";
export * from "./event";
export * from "./analysis";
export * from "./mitre";
export * from "./threatIntel";
export * from "./report";
export * from "./evaluation";
