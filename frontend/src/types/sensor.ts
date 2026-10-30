/** Mirrors the sensor-page routes (backend/app/models/sensor.py). Dates are ISO strings. */

/** A derived value and where it came from; `unknown` says nothing could be derived. */
export interface Described {
  value: string;
  source: "observed" | "persona" | "evaluation" | "unknown";
}

/** A stretch of time between two configuration changes. */
export interface SensorPeriod {
  start: string;
  end: string;
  /** The persona in force; "pre-persona" before the first deployment or after a revert; null if never. */
  persona: string | null;
  /** What opened it (`persona:<name>`, a change kind); empty for the first period. */
  openedBy: string[];
}

export interface SensorDeployment {
  persona: string;
  digest: string;
  deployedAt: string;
  deployedBy: string;
}

export interface SensorChange {
  kind: string;
  detail: string;
  at: string;
  recordedBy: string;
}

/** GET /api/honeypots/{id} */
export interface SensorProfile {
  id: string;
  name: string;
  /** Protocol -> event count. */
  protocols: Record<string, number>;
  address: string;
  firstSeen: string;
  lastSeen: string;
  type: Described;
  os: Described;
  /** Oldest first. */
  deployments: SensorDeployment[];
  changes: SensorChange[];
  /** Over the sensor's whole observed life. */
  periods: SensorPeriod[];
}

/** One UTC day. Distinct counts are per day, so they are not additive across days. */
export interface SensorDayPoint {
  day: string;
  events: number;
  sessions: number;
  sources: number;
}

export interface SensorSource {
  ip: string;
  country: string | null;
  events: number;
}

export interface SensorPeriodTraffic {
  period: SensorPeriod;
  events: number;
  sessions: number;
  sources: number;
  eventsPerDay: number;
  sessionsPerDay: number;
  sourcesPerDay: number;
}

/**
 * GET /api/honeypots/{id}/traffic?days=N. N+1 UTC days (first and last are
 * partial). Sessions and sources are approximate above 3,000 per day and 10,000
 * per period. `sourcesPerDay` is distinct sources over the period's length; it
 * does not compare between periods of different length (repeat sources).
 */
export interface SensorTraffic {
  days: number;
  perDay: SensorDayPoint[];
  topSources: SensorSource[];
  protocols: Record<string, number>;
  periods: SensorPeriodTraffic[];
}

export interface SensorTechnique {
  techniqueId: string;
  name: string;
  tactic: string;
  ruleId: string;
  events: number;
  sessions: number;
  firstSeen: string;
  lastSeen: string;
  /** Aligned with SensorTechniques.periods. */
  perPeriod: number[];
}

/**
 * GET /api/honeypots/{id}/techniques?days=N. Rule-matched over distinct command
 * lines (up to 1024 characters); `truncated` means more distinct commands
 * existed than were considered.
 */
export interface SensorTechniques {
  days: number;
  commandsConsidered: number;
  truncated: boolean;
  periods: SensorPeriod[];
  techniques: SensorTechnique[];
}
