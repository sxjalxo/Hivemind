import { cn } from "@/lib/utils";
import type { ServiceStatus } from "@/types";

const STATE_STYLE: Record<ServiceStatus["state"], { dot: string; text: string; label: string }> = {
  connected: { dot: "bg-success", text: "text-success", label: "Connected" },
  running: { dot: "bg-success", text: "text-success", label: "Running" },
  degraded: { dot: "bg-medium", text: "text-medium", label: "Degraded" },
  disconnected: { dot: "bg-critical", text: "text-critical", label: "Disconnected" },
  unknown: { dot: "bg-muted-foreground", text: "text-muted-foreground", label: "Unknown" },
};

export function StatusDot({
  state,
  pulse = true,
  className,
}: {
  state: ServiceStatus["state"];
  pulse?: boolean;
  className?: string;
}) {
  const healthy = state === "connected" || state === "running";
  return (
    <span
      className={cn(
        "size-1.5 shrink-0 rounded-full",
        STATE_STYLE[state].dot,
        pulse && healthy && "pulse-dot",
        className,
      )}
      aria-hidden
    />
  );
}

/** Reusable service health row — reused in the sidebar, top bar and live analysis panel. */
export function StatusRow({
  status,
  className,
  dense = false,
}: {
  status: ServiceStatus;
  className?: string;
  dense?: boolean;
}) {
  const style = STATE_STYLE[status.state];
  return (
    <div
      className={cn(
        "flex items-center justify-between gap-3",
        dense ? "py-0.5" : "py-1",
        className,
      )}
      title={status.detail ?? style.label}
    >
      <span className="flex min-w-0 items-center gap-2">
        <StatusDot state={status.state} />
        <span className="truncate text-xs text-muted-foreground">{status.name}</span>
      </span>
      <span className={cn("font-mono text-[10px] uppercase tracking-[0.08em]", style.text)}>
        {status.detail ?? style.label}
      </span>
    </div>
  );
}

export { STATE_STYLE };
