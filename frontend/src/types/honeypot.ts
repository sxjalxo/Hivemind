import type { Described } from "./sensor";

export type HoneypotStatus = "online" | "offline" | "degraded";

/**
 * Mirrors GET /api/honeypots. `type` and `os` are derived with their source
 * named. There is no interaction level and no risk: nothing measures either
 * for a sensor (the API still sends `risk: "unknown"`, which is not rendered).
 */
export interface Honeypot {
  id: string;
  name: string;
  type: Described;
  os: Described;
  ip: string;
  status: HoneypotStatus;
  activeSessions: number;
  events: number;
  lastActivity: string;
  sensor?: string | undefined;
  location?: string | undefined;
}
