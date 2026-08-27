import type { RiskLevel } from "./index";

/** ECS-style honeypot event, shaped to map directly onto Elasticsearch documents. */
export interface HoneypotEvent {
  id: string;
  timestamp: string;
  source: { ip: string; port?: number | undefined; country?: string | undefined };
  destination: { ip?: string | undefined; port?: number | undefined };
  event: { action: string; category: string; outcome?: string | undefined };
  network: { protocol: string };
  user?: { name?: string | undefined } | undefined;
  process?: { commandLine?: string | undefined; output?: string | undefined } | undefined;
  honeypot: { name: string; id: string };
  session: { id: string };
  risk: { score: number; level: RiskLevel };
  mitre?: { techniqueId?: string | undefined; tactic?: string | undefined } | undefined;
  aiClassification?: string | undefined;
  raw?: Record<string, unknown> | undefined;
}

export interface LogQuery {
  q?: string | undefined;
  honeypotId?: string | undefined;
  sourceIp?: string | undefined;
  destinationIp?: string | undefined;
  protocol?: string | undefined;
  eventCategory?: string | undefined;
  risk?: RiskLevel | undefined;
  techniqueId?: string | undefined;
  sessionId?: string | undefined;
  from?: string | undefined;
  to?: string | undefined;
  page?: number | undefined;
  pageSize?: number | undefined;
}
