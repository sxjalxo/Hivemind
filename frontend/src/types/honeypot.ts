import type { RiskLevel } from "./index";

export type HoneypotType = "SSH" | "HTTP" | "Telnet" | "Automotive" | "SMB" | "ICS";
export type InteractionLevel = "low" | "medium" | "high";
export type HoneypotStatus = "online" | "offline" | "degraded";

/** Mirrors GET /api/honeypots */
export interface Honeypot {
  id: string;
  name: string;
  type: HoneypotType;
  os: string;
  interactionLevel: InteractionLevel;
  ip: string;
  status: HoneypotStatus;
  activeSessions: number;
  events: number;
  lastActivity: string;
  risk: RiskLevel;
  sensor?: string | undefined;
  location?: string | undefined;
}
