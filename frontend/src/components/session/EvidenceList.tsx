import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ChevronRight } from "lucide-react";
import { useState } from "react";
import { CopyButton, ErrorState, LoadingState } from "@/components/common";
import { provider } from "@/services";
import { formatDateTime, formatTime } from "@/utils/format";
import { cn } from "@/lib/utils";
import type { EvidenceRef } from "@/types";

/**
 * Every AI conclusion in this product must be traceable to raw telemetry.
 * This renders that trail: the exact artefact, the session it came from and
 * when it was recorded — and, on demand, the full source event the pointer
 * resolves to, so an unresolvable eventId is never silently invisible.
 */
export function EvidenceList({
  evidence,
  className,
  dense = false,
}: {
  evidence: EvidenceRef[];
  className?: string;
  dense?: boolean;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (evidence.length === 0) {
    return (
      <p className={cn("text-xs italic text-muted-foreground", className)}>
        No supporting evidence was attached to this conclusion.
      </p>
    );
  }

  return (
    <ul className={cn("space-y-1", className)}>
      {evidence.map((item, index) => {
        const isOpen = expandedId === item.eventId;
        return (
          <li
            key={`${item.sessionId}-${item.artifact}-${index}`}
            className="rounded border border-border/70 bg-background/50"
          >
            <div className={cn("group flex items-start gap-2 px-2 py-1.5", dense && "px-1.5 py-1")}>
              <button
                type="button"
                onClick={() => setExpandedId(isOpen ? null : item.eventId)}
                aria-expanded={isOpen}
                aria-label={isOpen ? "Collapse source event" : "Expand source event"}
                className="mt-[1px] shrink-0 text-muted-foreground transition-colors hover:text-foreground"
              >
                <ChevronRight
                  className={cn("size-3.5 transition-transform", isOpen && "rotate-90")}
                  aria-hidden
                />
              </button>
              <span className="mt-[3px] shrink-0 select-none font-mono text-[11px] text-success">
                $
              </span>
              <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-[12px] text-foreground/90">
                {item.artifact}
              </code>
              <span className="flex shrink-0 items-center gap-1.5">
                <span className="font-mono text-[10px] text-muted-foreground">
                  {formatTime(item.timestamp)}
                </span>
                <Link
                  to="/sessions/$sessionId"
                  params={{ sessionId: item.sessionId }}
                  className="font-mono text-[10px] text-muted-foreground underline-offset-2 hover:text-primary hover:underline"
                  title={`Open ${item.sessionId}`}
                >
                  {item.sessionId}
                </Link>
                <CopyButton
                  value={item.artifact}
                  className="opacity-0 group-hover:opacity-100 focus:opacity-100"
                />
              </span>
            </div>
            {isOpen ? <SourceEvent eventId={item.eventId} /> : null}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * Resolves an evidence pointer to its source event on first expand.
 *
 * A dead pointer is exactly the failure this feature exists to surface, so a
 * resolution error is shown inline with the event id rather than swallowed.
 */
function SourceEvent({ eventId }: { eventId: string }) {
  const {
    data: sourceEvent,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["event", eventId],
    queryFn: () => provider.getEvent(eventId),
  });

  if (isLoading) {
    return (
      <div className="border-t border-border/70">
        <LoadingState message="Resolving source event..." className="py-4" />
      </div>
    );
  }

  if (isError || !sourceEvent) {
    return (
      <div className="border-t border-border/70">
        <ErrorState
          title="Source event not found"
          description={`Event ${eventId} could not be resolved${error instanceof Error ? `: ${error.message}` : "."}`}
          className="py-4"
        />
      </div>
    );
  }

  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-2 border-t border-border/70 px-3 py-2.5 sm:grid-cols-4">
      <div>
        <dt className="label-caps">Timestamp</dt>
        <dd className="mt-0.5 font-mono text-[11px] text-foreground/90">
          {formatDateTime(sourceEvent.timestamp)}
        </dd>
      </div>
      <div>
        <dt className="label-caps">Action</dt>
        <dd className="mt-0.5 font-mono text-[11px] text-foreground/90">
          {sourceEvent.event.action}
        </dd>
      </div>
      <div>
        <dt className="label-caps">Source IP</dt>
        <dd className="mt-0.5 font-mono text-[11px] text-foreground/90">{sourceEvent.source.ip}</dd>
      </div>
      <div>
        <dt className="label-caps">Event id</dt>
        <dd className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
          {sourceEvent.id}
        </dd>
      </div>
      <div className="col-span-2 sm:col-span-4">
        <dt className="label-caps">Command line</dt>
        <dd className="mt-0.5 whitespace-pre-wrap break-all font-mono text-[11px] text-foreground/90">
          {sourceEvent.process?.commandLine ?? "— no process command recorded on this event —"}
        </dd>
      </div>
    </dl>
  );
}
