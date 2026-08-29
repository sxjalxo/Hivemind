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

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, query, signal } = options;
  const init: RequestInit = { method };
  if (signal) init.signal = signal;
  if (body !== undefined) {
    init.headers = { "content-type": "application/json" };
    init.body = JSON.stringify(body);
  }
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
} as const;
