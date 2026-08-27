import type { EvidenceRef } from "./analysis";

export const MITRE_TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

export type MitreTactic = (typeof MITRE_TACTICS)[number];

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: MitreTactic;
  /** Observed in honeypot telemetry within the selected scope. */
  observed: boolean;
  sessionCount: number;
  confidence?: number | undefined;
  evidence: EvidenceRef[];
  relatedCommands: string[];
  aiExplanation?: string | undefined;
  lastSeen?: string | undefined;
}

export interface MitreCoverage {
  techniques: MitreTechnique[];
  observedCount: number;
  totalCount: number;
}
