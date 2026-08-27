import type { RiskLevel } from "./index";

export type AnalysisState = "not_analyzed" | "queued" | "analyzing" | "completed" | "failed";

export interface AttackSession {
  id: string;
  attackerIp: string;
  sourcePort: number;
  destinationPort: number;
  honeypotId: string;
  honeypotName: string;
  protocol: string;
  startedAt: string;
  endedAt?: string | undefined;
  durationSeconds: number;
  commandCount: number;
  riskScore: number;
  risk: RiskLevel;
  /** Ordered tactic chain, e.g. ["Credential Access", "Discovery", "Execution"]. */
  classificationChain: string[];
  mitreTechniqueIds: string[];
  analysisState: AnalysisState;
  country?: string | undefined;
  username?: string | undefined;
}

export interface SessionTimelineEvent {
  id: string;
  timestamp: string;
  kind: "connection" | "auth" | "command" | "download" | "file" | "execution" | "disconnect";
  label: string;
  detail?: string | undefined;
  severity: RiskLevel;
  techniqueId?: string | undefined;
}

export interface AttackerProfile {
  ip: string;
  risk: RiskLevel;
  riskScore: number;
  behaviorLabel: string;
  sessions: number;
  firstSeen: string;
  lastSeen: string;
  targetedHoneypots: string[];
  commands: string[];
  techniqueIds: string[];
  downloadedFiles: { name: string; sha256: string; size: number }[];
  indicatorIds: string[];
  geo: { country?: string; asn?: string; org?: string } | null;
  /** Behavioral similarity to other known attackers, 0-1. */
  similarity: { ip: string; score: number }[];
  attackPattern: string[];
}
