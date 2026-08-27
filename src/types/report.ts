import type { RiskLevel } from "./index";
import type { TechniqueMapping } from "./analysis";
import type { Indicator } from "./threatIntel";
import type { SessionTimelineEvent } from "./session";

export interface ThreatReport {
  id: string;
  title: string;
  sessionId: string;
  createdAt: string;
  generatedBy: string;
  executiveSummary: string;
  incidentOverview: {
    attackerIp: string;
    target: string;
    timeRange: string;
    protocol: string;
    risk: RiskLevel;
    riskScore: number;
  };
  timeline: SessionTimelineEvent[];
  attackerBehavior: { classification: string; explanation: string; confidence: number };
  mitre: TechniqueMapping[];
  indicators: Indicator[];
  threatAssessment: { level: RiskLevel; confidence: number; narrative: string };
  recommendedActions: { priority: "P1" | "P2" | "P3"; action: string; rationale: string }[];
}
