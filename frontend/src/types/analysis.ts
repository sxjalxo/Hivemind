import type { RiskLevel } from "./index";

export type AnalysisStage =
  | "parsing_logs"
  | "identifying_patterns"
  | "classifying_behavior"
  | "extracting_indicators"
  | "mapping_mitre"
  | "generating_intel"
  | "generating_recommendations";

export interface AnalysisProgress {
  stage: AnalysisStage;
  label: string;
  state: "pending" | "active" | "done";
}

export interface EvidenceRef {
  /** Raw observed artifact (command, log line, header). */
  artifact: string;
  sessionId: string;
  timestamp?: string | undefined;
  eventId?: string | undefined;
}

export interface TechniqueMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  confidence: number;
  evidence: EvidenceRef[];
  relatedCommands: string[];
  aiExplanation: string;
  timestamp: string;
}

/** Mirrors POST /api/analyze/{session_id} and GET /api/analysis/{id} */
export interface SessionAnalysis {
  id: string;
  sessionId: string;
  model: string;
  analysisType: string;
  status: "queued" | "running" | "completed" | "failed";
  createdAt: string;
  durationSeconds: number;
  classification: string;
  confidence: number;
  riskScore: number;
  risk: RiskLevel;
  behaviorSummary: string;
  observedBehavior: { label: string; evidence: EvidenceRef[] }[];
  suspiciousIndicators: { label: string; severity: RiskLevel; evidence: EvidenceRef[] }[];
  recommendedActions: { priority: "P1" | "P2" | "P3"; action: string; rationale: string }[];
  techniques: TechniqueMapping[];
}

export interface LiveAnalysisState {
  sessionId: string;
  progressPct: number;
  eventsProcessed: number;
  commandsAnalyzed: number;
  techniquesDetected: number;
  iocsExtracted: number;
}
