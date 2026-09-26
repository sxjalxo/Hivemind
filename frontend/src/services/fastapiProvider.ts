import { API_BASE_URL, endpoints, request, wsProtocols } from "./api";
import type { AnalysisProgressEvent, DashboardData, DataProvider, Unsubscribe } from "./provider";
import type {
  AttackSession,
  AttackerProfile,
  EvaluationProgressEvent,
  EvaluationRemediation,
  EvaluationRun,
  EvaluationRunSummary,
  Honeypot,
  HoneypotEvent,
  Indicator,
  MitreCoverage,
  Paginated,
  RunComparison,
  ServiceStatus,
  SessionAnalysis,
  SessionTimelineEvent,
  StartEvaluationResponse,
  ThreatReport,
} from "@/types";

/**
 * FastAPIProvider — the production data path. Every method is a thin mapping
 * onto the documented backend contract; no data is fabricated here.
 */
export const FastAPIProvider: DataProvider = {
  mode: "api",

  getSystemStatus: () => request<ServiceStatus[]>(endpoints.status),

  getHoneypots: () => request<Honeypot[]>(endpoints.honeypots),

  getSessions: (params) =>
    request<AttackSession[]>(endpoints.sessions, {
      query: { risk: params?.risk, honeypotId: params?.honeypotId, q: params?.q },
    }),

  getSession: (id) => request<AttackSession>(endpoints.session(id)),

  getSessionTimeline: (id) => request<SessionTimelineEvent[]>(`${endpoints.session(id)}/timeline`),

  getSessionEvents: (id) => request<HoneypotEvent[]>(`${endpoints.session(id)}/events`),

  queryLogs: (query) =>
    request<Paginated<HoneypotEvent>>(endpoints.logs, {
      query: {
        q: query.q,
        honeypotId: query.honeypotId,
        sourceIp: query.sourceIp,
        destinationIp: query.destinationIp,
        protocol: query.protocol,
        eventCategory: query.eventCategory,
        risk: query.risk,
        techniqueId: query.techniqueId,
        sessionId: query.sessionId,
        from: query.from,
        to: query.to,
        page: query.page,
        pageSize: query.pageSize,
      },
    }),

  getEvent: (eventId) => request<HoneypotEvent>(endpoints.event(eventId)),

  analyzeSession: (sessionId, signal) =>
    request<SessionAnalysis>(endpoints.analyze(sessionId), { method: "POST", signal }),

  getAnalysis: (id) => request<SessionAnalysis>(endpoints.analysis(id)),

  getAnalysisHistory: () => request<SessionAnalysis[]>(endpoints.analyses),

  /**
   * Live stage channel for a running analysis.
   *
   * Connects to WS /api/analyze/{session_id}/progress and forwards each
   * AnalysisProgressEvent frame to the caller. Its presence is what tells the
   * UI to animate the stepper from real backend stages instead of falling
   * back to an indeterminate running state.
   */
  async subscribeAnalysisProgress(sessionId, onEvent): Promise<Unsubscribe> {
    const wsBase = API_BASE_URL.replace(/^http/, "ws");
    const socket = new WebSocket(
      `${wsBase}${endpoints.analyze(sessionId)}/progress`,
      await wsProtocols(),
    );

    socket.onmessage = (message) => {
      onEvent(JSON.parse(message.data as string) as AnalysisProgressEvent);
    };

    // Resolve only once the socket is actually open. `new WebSocket` returns
    // immediately with the handshake still in flight, so posting right after
    // this call raced the connection: the backend publishes stage 0 as soon
    // as the analysis starts and the channel has no replay, so whichever
    // early stages landed before the handshake finished were gone. It looked
    // like a flickering stepper rather than a bug, and it varied run to run.
    return new Promise<Unsubscribe>((resolve) => {
      const done = () => resolve(() => socket.close());
      if (socket.readyState === WebSocket.OPEN) {
        done();
        return;
      }
      socket.addEventListener("open", done, { once: true });
      // Resolve on failure too, never reject. A progress channel that could
      // not connect must not stop the analysis from running -- the UI already
      // knows how to show an indeterminate state, and the result is read back
      // from the API regardless. Rejecting here would turn a cosmetic
      // degradation into a failed analysis.
      socket.addEventListener("error", done, { once: true });
      socket.addEventListener("close", done, { once: true });
    });
  },

  getMitreCoverage: (params) =>
    request<MitreCoverage>(endpoints.mitre, { query: { sessionId: params?.sessionId } }),

  getIndicators: (params) =>
    request<Indicator[]>(endpoints.threatIntel, { query: { type: params?.type, q: params?.q } }),

  getAttackerProfile: (ip) => request<AttackerProfile>(endpoints.attacker(ip)),

  getReports: () => request<ThreatReport[]>(endpoints.reports),

  createReport: (sessionId) =>
    request<ThreatReport>(endpoints.reports, { method: "POST", body: { sessionId } }),

  getDashboard: (range) => request<DashboardData>("/api/dashboard", { query: { range } }),

  listEvaluations: (limit) =>
    request<EvaluationRunSummary[]>(endpoints.evaluations, { query: { limit } }),

  getEvaluation: (id) => request<EvaluationRun>(endpoints.evaluation(id)),

  /**
   * POST /api/evaluations — 202 Accepted with only { runId }.
   *
   * The body is camelCase because StartEvaluationRequest declares camelCase
   * aliases AND extra="forbid": a snake_case key or one extra field is a 422,
   * not a silently ignored one.
   */
  startEvaluation: (honeypotId) =>
    request<StartEvaluationResponse>(endpoints.evaluations, {
      method: "POST",
      body: { honeypotId },
    }),

  compareEvaluations: (base, head) =>
    request<RunComparison>(endpoints.evaluationCompare, { query: { base, head } }),

  getEvaluationRemediation: (runId) =>
    request<EvaluationRemediation[]>(endpoints.evaluationRemediation(runId)),

  /**
   * Live stage channel for a running evaluation.
   *
   * Connects to WS /api/evaluations/{run_id}/progress and forwards each
   * EvaluationProgressEvent frame. `runId` must be the exact string the 202
   * returned: the route parses it as a UUID, so anything else is rejected at
   * the handshake with a 403.
   *
   * There is no replay and no completion frame — a socket opened after the run
   * finished stays silent. The one frame that matters on its own is the
   * terminal `failed` frame, which reports a run that never got a row and so
   * has no GET to read back.
   */
  async subscribeEvaluationProgress(runId, onEvent): Promise<Unsubscribe> {
    const wsBase = API_BASE_URL.replace(/^http/, "ws");
    const socket = new WebSocket(
      `${wsBase}${endpoints.evaluation(runId)}/progress`,
      await wsProtocols(),
    );

    socket.onmessage = (message) => {
      onEvent(JSON.parse(message.data as string) as EvaluationProgressEvent);
    };

    return () => socket.close();
  },
};
