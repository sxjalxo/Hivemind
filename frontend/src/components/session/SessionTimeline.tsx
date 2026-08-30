import {
  CircleHelp,
  Download,
  FileCog,
  KeyRound,
  LogOut,
  Network,
  Play,
  Plug,
  Share2,
  TerminalSquare,
  type LucideIcon,
} from "lucide-react";
import { MitreBadge, Mono, ProvenanceBadge } from "@/components/common";
import { SEVERITY_COLOR } from "@/components/charts/palette";
import { formatTime } from "@/utils/format";
import { cn } from "@/lib/utils";
import type { SessionTimelineEvent } from "@/types";

const KIND_ICON: Record<SessionTimelineEvent["kind"], LucideIcon> = {
  connection: Plug,
  auth: KeyRound,
  command: TerminalSquare,
  download: Download,
  file: FileCog,
  execution: Play,
  tunnel: Share2,
  protocol: Network,
  other: CircleHelp,
  disconnect: LogOut,
};

/**
 * Chronological attack timeline. Every row is raw honeypot evidence, so the
 * whole block is marked OBSERVED — AI interpretation lives in its own panel.
 */
export function SessionTimeline({
  events,
  onSelect,
  selectedId,
}: {
  events: SessionTimelineEvent[];
  onSelect?: (event: SessionTimelineEvent) => void;
  selectedId?: string;
}) {
  return (
    <ol className="relative space-y-0">
      <span className="absolute bottom-3 left-[15px] top-3 w-px bg-border" aria-hidden />
      {events.map((event) => {
        const Icon = KIND_ICON[event.kind];
        const color = SEVERITY_COLOR[event.severity];
        const selected = selectedId === event.id;

        return (
          <li key={event.id} className="relative">
            <button
              type="button"
              onClick={() => onSelect?.(event)}
              disabled={!onSelect}
              className={cn(
                "flex w-full items-start gap-3 rounded-md px-1.5 py-2 text-left transition-colors",
                onSelect && "hover:bg-accent/30",
                selected && "bg-accent/40",
              )}
            >
              <span
                className="relative z-10 mt-0.5 flex size-[27px] shrink-0 items-center justify-center rounded-full border bg-card"
                style={{ borderColor: color }}
              >
                <Icon className="size-3.5" style={{ color }} aria-hidden />
              </span>

              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
                  <Mono tone="muted" className="text-xs">
                    {formatTime(event.timestamp)}
                  </Mono>
                  <span className="text-sm text-foreground">{event.label}</span>
                  {event.techniqueId ? <MitreBadge techniqueId={event.techniqueId} /> : null}
                </span>
                {event.detail ? (
                  <span className="mt-1 block truncate font-mono text-xs text-muted-foreground">
                    {event.detail}
                  </span>
                ) : null}
              </span>
            </button>
          </li>
        );
      })}

      <li className="pt-2">
        <ProvenanceBadge kind="OBSERVED" className="ml-1" />
      </li>
    </ol>
  );
}
