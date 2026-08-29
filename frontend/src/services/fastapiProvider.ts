import { API_BASE_URL, endpoints, request } from "./api";
import type { AnalysisProgressEvent, DashboardData, DataProvider, Unsubscribe } from "./provider";
import type {
  AttackSession,
  AttackerProfile,
  Honeypot,
  HoneypotEvent,
  Indicator,
  MitreCoverage,
  Paginated,
  ServiceStatus,
  SessionAnalysis,
  SessionTimelineEvent,
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
  subscribeAnalysisProgress(sessionId, onEvent): Unsubscribe {
    const wsBase = API_BASE_URL.replace(/^http/, "ws");
    const socket = new WebSocket(`${wsBase}${endpoints.analyze(sessionId)}/progress`);

    socket.onmessage = (message) => {
      onEvent(JSON.parse(message.data as string) as AnalysisProgressEvent);
    };

    return () => socket.close();
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
};
