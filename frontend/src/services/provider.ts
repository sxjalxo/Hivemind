import type {
  AnalysisStage,
  AttackSession,
  AttackerProfile,
  EvaluationProgressEvent,
  EvaluationRun,
  EvaluationRunSummary,
  Honeypot,
  HoneypotEvent,
  Indicator,
  LiveAnalysisState,
  LogQuery,
  MitreCoverage,
  Paginated,
  RunComparison,
  ServiceStatus,
  SessionAnalysis,
  SessionTimelineEvent,
  StartEvaluationResponse,
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
   *
   * Returns a PROMISE, resolving once the channel is actually listening, and
   * the caller must await it before starting the analysis. The backend
   * publishes its first stage the moment the analysis begins and the channel
   * has no replay, so a socket still completing its handshake misses however
   * many stages it takes to finish -- silently, and differently on every run.
   *
   * This channel is keyed by the session id, which the caller already holds
   * before it posts, so subscribing first closes the window completely.
   * `subscribeEvaluationProgress` below is a promise too, but for a second
   * reason: it must fetch a Clerk token before opening the socket. Awaiting
   * does NOT close its ordering gap — its key is a run id the server
   * allocates, so the client cannot subscribe until the POST has returned
   * and the run is already under way. That gap is real, documented, and
   * closed by reading the outcome back from the API, not from the socket.
   */
  subscribeAnalysisProgress?(
    sessionId: string,
    onEvent: (event: AnalysisProgressEvent) => void,
  ): Promise<Unsubscribe>;

  getMitreCoverage(params?: { sessionId?: string }): Promise<MitreCoverage>;

  getIndicators(params?: { type?: string; q?: string }): Promise<Indicator[]>;
  getAttackerProfile(ip: string): Promise<AttackerProfile>;

  getReports(): Promise<ThreatReport[]>;
  createReport(sessionId: string): Promise<ThreatReport>;

  /**
   * Bounded history rows, newest first. NOT full runs: a summary carries no
   * findings, modules, chain steps or probe results. Read one run in full with
   * getEvaluation.
   *
   * `limit` defaults to DEFAULT_EVALUATION_LIMIT server-side and is capped at
   * MAX_EVALUATION_LIMIT — 101 or more is rejected with a 422, not clamped.
   */
  listEvaluations(limit?: number): Promise<EvaluationRunSummary[]>;

  /**
   * One run in full, and the authoritative record of what it established.
   *
   * A 404 is not always "not yet started": a run that failed before its row
   * existed 404s permanently, and its only record is the terminal progress
   * frame. Do not poll this forever waiting for a row that will never appear.
   */
  getEvaluation(id: string): Promise<EvaluationRun>;

  /**
   * Dispatch a run. Resolves with only a run id — the run has NOT happened yet
   * (the backend answers 202 Accepted). Take the id, subscribe to progress with
   * that exact string, then getEvaluation when the run ends.
   *
   * Rejects with a 409 when an evaluation is already running for that honeypot.
   */
  startEvaluation(honeypotId: string): Promise<StartEvaluationResponse>;

  /**
   * Delta between two runs. Never refused: a configuration change is reported
   * in `classification` and `differences` rather than hidden by a refusal.
   */
  compareEvaluations(base: string, head: string): Promise<RunComparison>;

  /**
   * Optional live stage channel for a running evaluation.
   *
   * Optional for the same reason as subscribeAnalysisProgress: a provider
   * without a real source of stage updates omits it, and the UI shows an
   * indeterminate running state rather than inventing progress.
   *
   * The channel has NO replay and NO completion frame. A subscription opened
   * after the run finished receives nothing, forever. Treat this as decoration
   * over getEvaluation, which is the authoritative record — except for the
   * terminal `failed` frame, which may be the ONLY record of a run that never
   * got a row.
   */
  subscribeEvaluationProgress?(
    runId: string,
    onEvent: (event: EvaluationProgressEvent) => void,
  ): Promise<Unsubscribe>;

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
