import type { RiskLevel } from "./index";

export type AnalysisState = "not_analyzed" | "queued" | "analyzing" | "completed" | "failed";

export interface AttackSession {
  id: string;
  attackerIp: string;
  /** null when the honeypot never recorded a port — never a fabricated 0. */
  sourcePort: number | null;
  destinationPort: number | null;
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
  /**
   * "protocol" is SSH transport/session metadata Cowrie records for every real
   * connection; "other" is an eventid the backend does not recognise. Neither
   * is attacker input, and neither may be rendered as a command. "tunnel" IS
   * attacker input — a port-forwarding request, the honeypot being asked to
   * relay traffic.
   */
  kind:
    | "connection"
    | "auth"
    | "command"
    | "download"
    | "file"
    | "execution"
    | "tunnel"
    | "protocol"
    | "other"
    | "disconnect";
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
  /** null when Cowrie's raw size was stripped as noise by the ingest pipeline — never a fabricated 0. */
  downloadedFiles: { name: string; sha256: string; size?: number | null }[];
  indicatorIds: string[];
  geo: { country?: string; asn?: string; org?: string } | null;
  /** Behavioral similarity to other known attackers, 0-1. Cut to the top few. */
  similarity: { ip: string; score: number }[];
  /** Neighbours scoring above zero in total, before `similarity` was truncated. */
  similarityTotal: number;
  /**
   * False when the command sets behind `similarity` were truncated by a
   * backend aggregation cap. `similarity` is then empty and must be presented
   * as unavailable, never as "no neighbours found" — the two mean opposite
   * things to an analyst.
   */
  similarityComplete: boolean;
  similarityIncompleteReason: string | null;
  attackPattern: string[];
}
