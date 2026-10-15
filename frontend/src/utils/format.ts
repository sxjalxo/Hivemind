import type { HoneypotEvent } from "@/types";

export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toISOString().slice(11, 19);
}

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return `${date.toISOString().slice(0, 10)} ${date.toISOString().slice(11, 19)}`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${minutes}m ${String(rest).padStart(2, "0")}s`;
}

/**
 * `undefined`/`null` means the source never recorded a size — distinct from an
 * observed 0. The backend serializes the omitted field as JSON `null`, so both
 * are treated the same way here.
 */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null) return "size unknown";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatPct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** An HTTP honeypot event as one line, e.g. `GET /.env → 404`; undefined for any other event. */
export function formatHttpRequest(event: HoneypotEvent): string | undefined {
  if (!event.url?.path) return undefined;
  const query = event.url.query ? `?${event.url.query}` : "";
  const status = event.http?.response?.statusCode;
  return `${event.http?.request?.method ?? "?"} ${event.url.path}${query}${status ? ` → ${status}` : ""}`;
}
