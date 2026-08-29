import type {
  AnalysisStage,
  AttackSession,
  AttackerProfile,
  Honeypot,
  HoneypotEvent,
  Indicator,
  LiveAnalysisState,
  LogQuery,
  MitreCoverage,
  Paginated,
  ServiceStatus,
  SessionAnalysis,
  SessionTimelineEvent,
  ThreatReport,
} from "@/types";

/** One progress tick emitted by the backend while an analysis runs. */
export interface AnalysisProgressEvent {
  /** Index into ANALYSIS_STAGES. */
  stageIndex: number;
  stage: AnalysisStage;
  metrics?: Partial<Omit<LiveAnalysisState, "sessionId">>;
}

export type Unsubscribe = () => void;

/**
 * Single contract implemented by both the demo provider and the FastAPI
 * provider. Swapping DemoProvider -> FastAPIProvider requires no UI changes.
 */
export interface DataProvider {
  readonly mode: "demo" | "api";

  getSystemStatus(): Promise<ServiceStatus[]>;

  getHoneypots(): Promise<Honeypot[]>;

  getSessions(params?: {
    risk?: string;
    honeypotId?: string;
    q?: string;
  }): Promise<AttackSession[]>;
  getSession(id: string): Promise<AttackSession>;
  getSessionTimeline(id: string): Promise<SessionTimelineEvent[]>;
  getSessionEvents(id: string): Promise<HoneypotEvent[]>;

  queryLogs(query: LogQuery): Promise<Paginated<HoneypotEvent>>;

  /**
   * Resolve an EvidenceRef to its source event.
   *
   * This is what makes an AI conclusion expandable into the exact log line
   * that produced it, rather than a quoted string with no provenance.
   */
  getEvent(eventId: string): Promise<HoneypotEvent>;

  analyzeSession(sessionId: string, signal?: AbortSignal): Promise<SessionAnalysis>;
  getAnalysis(id: string): Promise<SessionAnalysis>;
  getAnalysisHistory(): Promise<SessionAnalysis[]>;

  /**
   * Optional live progress channel for a running analysis.
   *
   * Present only when the provider has a real source of stage updates. When it
   * is absent the UI shows an indeterminate running state rather than inventing
   * progress, so a spinner never implies knowledge the backend did not send.
   */
  subscribeAnalysisProgress?(
    sessionId: string,
    onEvent: (event: AnalysisProgressEvent) => void,
  ): Unsubscribe;

  getMitreCoverage(params?: { sessionId?: string }): Promise<MitreCoverage>;

  getIndicators(params?: { type?: string; q?: string }): Promise<Indicator[]>;
  getAttackerProfile(ip: string): Promise<AttackerProfile>;

  getReports(): Promise<ThreatReport[]>;
  createReport(sessionId: string): Promise<ThreatReport>;

  getDashboard(range: string): Promise<DashboardData>;
}

export interface DashboardKpi {
  id: string;
  label: string;
  value: number;
  trendPct: number;
  trendDirection: "up" | "down" | "flat";
  tone: "default" | "critical" | "high" | "info" | "ai";
}

export interface DashboardData {
  kpis: DashboardKpi[];
  timeline: { t: string; events: number; highRisk: number }[];
  classifications: { name: string; value: number }[];
  riskDistribution: { level: string; value: number }[];
  topAttackers: {
    ip: string;
    country: string;
    events: number;
    sessions: number;
    risk: string;
    lastSeen: string;
  }[];
  topCommands: { command: string; count: number; techniqueId?: string }[];
}
