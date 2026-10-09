/**
 * HTTP transport for the FastAPI backend.
 *
 * The base URL is configurable and NEVER contains Elasticsearch or Ollama
 * credentials — the backend owns those. The frontend only talks to FastAPI.
 */
export const API_BASE_URL: string =
  (import.meta.env["VITE_API_BASE_URL"] as string | undefined)?.replace(/\/$/, "") ??
  "http://localhost:8000";

/** Demo mode is on unless an API base URL is explicitly configured. */
export const DEMO_MODE: boolean = !import.meta.env["VITE_API_BASE_URL"];

/**
 * Whether this build has authentication at all.
 *
 * Clerk needs a publishable key in the bundle. Without one there is no
 * identity: ClerkProvider still mounts, but no session and no claims ever
 * arrive, so every role check resolves to the `viewer` floor and every
 * admin-gated control renders disabled — while the backend, configured the
 * same way, is fail-open and answers every caller ("OPEN — every route
 * answers any caller", as its own status row says). A UI stricter than the
 * backend it fronts is not a security boundary, it is a broken install: it
 * hides working features and explains itself with a tooltip asking for a
 * role that cannot be granted.
 *
 * Mirrors `clerkConfigured` in `start.ts`, which makes the same call for the
 * server middleware.
 */
export const AUTH_CONFIGURED: boolean = Boolean(import.meta.env["VITE_CLERK_PUBLISHABLE_KEY"]);

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE" | undefined;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined> | undefined;
  signal?: AbortSignal | undefined;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const url = new URL(`${API_BASE_URL}${path}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== "") url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

/**
 * The current Clerk session token, or null when there is no session.
 *
 * Read off `window.Clerk` rather than a React hook because this module is the
 * plain transport layer -- it is called from query functions and mutations
 * that are not components and have no hook context. clerk-js sets the global
 * as soon as ClerkProvider loads.
 *
 * Returns null rather than throwing when Clerk is absent, which is the
 * ordinary case in demo mode and against a backend with `CLERK_ISSUER` unset.
 * The request then goes out unauthenticated and the backend decides: open
 * deployments serve it, configured ones answer 401. Failing here instead
 * would break demo mode, which has no Clerk at all.
 */
export async function sessionToken(): Promise<string | null> {
  const clerk = (globalThis as { Clerk?: { session?: { getToken(): Promise<string | null> } } })
    .Clerk;
  if (!clerk?.session) return null;
  try {
    return await clerk.session.getToken();
  } catch {
    // A refresh failure must not take the request down with it -- let the
    // backend answer 401 and the UI surface that, rather than throwing a
    // transport error the caller cannot interpret.
    return null;
  }
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, query, signal } = options;
  const init: RequestInit = { method };
  if (signal) init.signal = signal;
  const headers: Record<string, string> = {};
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const token = await sessionToken();
  if (token) headers["authorization"] = `Bearer ${token}`;
  if (Object.keys(headers).length > 0) init.headers = headers;
  const response = await fetch(buildUrl(path, query), init);

  if (!response.ok) {
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      payload = undefined;
    }
    throw new ApiError(`${method} ${path} failed (${response.status})`, response.status, payload);
  }

  return (await response.json()) as T;
}

/**
 * Subprotocols carrying the Clerk token onto a WebSocket handshake.
 *
 * A browser cannot set an Authorization header on `new WebSocket`, and the
 * token must NOT go in the query string: URLs reach access logs, proxy logs
 * and browser history, and a session token is a bearer credential. The
 * subprotocol header is the one channel a browser will send on a handshake.
 *
 * Two values are offered because the server must echo exactly one offered
 * protocol or the browser fails the connection -- it echoes the bare marker
 * and reads the token from the other. Returns [] when there is no session, so
 * demo mode and an open backend still connect.
 */
export async function wsProtocols(): Promise<string[]> {
  const token = await sessionToken();
  return token ? ["clerk", `clerk-token.${token}`] : [];
}

/** Endpoint map kept in one place so the backend contract is reviewable. */
export const endpoints = {
  honeypots: "/api/honeypots",
  sessions: "/api/sessions",
  session: (id: string) => `/api/sessions/${id}`,
  event: (id: string) => `/api/events/${encodeURIComponent(id)}`,
  logs: "/api/logs",
  analyze: (sessionId: string) => `/api/analyze/${sessionId}`,
  analysis: (id: string) => `/api/analysis/${id}`,
  analyses: "/api/analysis",
  mitre: "/api/mitre",
  threatIntel: "/api/threat-intelligence",
  reports: "/api/reports",
  status: "/api/status",
  attacker: (ip: string) => `/api/attackers/${encodeURIComponent(ip)}`,
  evaluations: "/api/evaluations",
  evaluation: (id: string) => `/api/evaluations/${encodeURIComponent(id)}`,
  evaluationCompare: "/api/evaluations/compare",
  evaluationRemediation: (id: string) => `/api/evaluations/${encodeURIComponent(id)}/remediation`,
} as const;
