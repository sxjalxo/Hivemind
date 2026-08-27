import { endpoints, request } from "./api";
import type { DashboardData, DataProvider } from "./provider";
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
      query: { risk: params?.risk, honeypot_id: params?.honeypotId, q: params?.q },
    }),

  getSession: (id) => request<AttackSession>(endpoints.session(id)),

  getSessionTimeline: (id) => request<SessionTimelineEvent[]>(`${endpoints.session(id)}/timeline`),

  getSessionEvents: (id) => request<HoneypotEvent[]>(`${endpoints.session(id)}/events`),

  queryLogs: (query) =>
    request<Paginated<HoneypotEvent>>(endpoints.logs, {
      query: {
        q: query.q,
        honeypot_id: query.honeypotId,
        "source.ip": query.sourceIp,
        "destination.ip": query.destinationIp,
        protocol: query.protocol,
        event_category: query.eventCategory,
        risk: query.risk,
        technique_id: query.techniqueId,
        session_id: query.sessionId,
        from: query.from,
        to: query.to,
        page: query.page,
        page_size: query.pageSize,
      },
    }),

  analyzeSession: (sessionId, signal) =>
    request<SessionAnalysis>(endpoints.analyze(sessionId), { method: "POST", signal }),

  getAnalysis: (id) => request<SessionAnalysis>(endpoints.analysis(id)),

  getAnalysisHistory: () => request<SessionAnalysis[]>(endpoints.analyses),

  // `subscribeAnalysisProgress` is intentionally NOT implemented here yet.
  //
  // The UI treats its absence as "no live stage channel" and shows an
  // indeterminate running state. Wire it up once the backend exposes
  // WS /api/analyze/{session_id}/progress, emitting AnalysisProgressEvent
  // frames; no UI change is required to light the stepper up.

  getMitreCoverage: (params) =>
    request<MitreCoverage>(endpoints.mitre, { query: { session_id: params?.sessionId } }),

  getIndicators: (params) =>
    request<Indicator[]>(endpoints.threatIntel, { query: { type: params?.type, q: params?.q } }),

  getAttackerProfile: (ip) => request<AttackerProfile>(endpoints.attacker(ip)),

  getReports: () => request<ThreatReport[]>(endpoints.reports),

  createReport: (sessionId) =>
    request<ThreatReport>(endpoints.reports, { method: "POST", body: { session_id: sessionId } }),

  getDashboard: (range) => request<DashboardData>("/api/dashboard", { query: { range } }),
};
