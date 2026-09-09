import { useQuery } from "@tanstack/react-query";
import { ChevronRight } from "lucide-react";
import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { ErrorState, LoadingState, Mono } from "@/components/common";
import { provider } from "@/services";
import { formatDateTime } from "@/utils/format";
import { cn } from "@/lib/utils";

/**
 * An event id that resolves to the real event, not a decorative string.
 *
 * Every claim in this surface has to reach its evidence, so a chain step's
 * `cowrieEventId` and a finding's `esEventId` are both expandable into the
 * event `DataProvider.getEvent` returns. A pointer that cannot be resolved is
 * shown as exactly that -- an unresolvable citation is a defect worth seeing,
 * not something to hide behind a plain string.
 */
export function EventDisclosure({ eventId, className }: { eventId: string; className?: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div className={cn("min-w-0", className)}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="inline-flex max-w-full items-center gap-1 rounded text-left underline-offset-2 hover:text-primary hover:underline"
        title={open ? "Collapse source event" : "Resolve this event id"}
      >
        <ChevronRight
          className={cn("size-3 shrink-0 transition-transform", open && "rotate-90")}
          aria-hidden
        />
        <Mono className="truncate text-[11px]">{eventId}</Mono>
      </button>
      {open ? <ResolvedEvent eventId={eventId} /> : null}
    </div>
  );
}

function ResolvedEvent({ eventId }: { eventId: string }) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["event", eventId],
    queryFn: () => provider.getEvent(eventId),
  });

  if (isLoading) {
    return (
      <div className="mt-1 rounded border border-border/70 bg-background/60">
        <LoadingState message="Resolving source event..." className="py-4" />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="mt-1 rounded border border-border/70 bg-background/60">
        <ErrorState
          title="Source event not found"
          description={`Event ${eventId} could not be resolved${
            error instanceof Error ? `: ${error.message}` : "."
          }`}
          className="py-4"
        />
      </div>
    );
  }

  return (
    <dl className="mt-1 grid grid-cols-2 gap-x-4 gap-y-2 rounded border border-border/70 bg-background/60 px-3 py-2.5 sm:grid-cols-4">
      <div>
        <dt className="label-caps">Timestamp</dt>
        <dd className="mt-0.5 font-mono text-[11px] text-foreground/90">
          {formatDateTime(data.timestamp)}
        </dd>
      </div>
      <div>
        <dt className="label-caps">Action</dt>
        <dd className="mt-0.5 font-mono text-[11px] text-foreground/90">{data.event.action}</dd>
      </div>
      <div>
        <dt className="label-caps">Source IP</dt>
        <dd className="mt-0.5 font-mono text-[11px] text-foreground/90">{data.source.ip}</dd>
      </div>
      <div>
        <dt className="label-caps">Session</dt>
        <dd className="mt-0.5 truncate font-mono text-[11px]">
          <Link
            to="/sessions/$sessionId"
            params={{ sessionId: data.session.id }}
            className="text-muted-foreground underline-offset-2 hover:text-primary hover:underline"
          >
            {data.session.id}
          </Link>
        </dd>
      </div>
      <div className="col-span-2 sm:col-span-4">
        <dt className="label-caps">Command line</dt>
        <dd className="mt-0.5 whitespace-pre-wrap break-all font-mono text-[11px] text-foreground/90">
          {data.process?.commandLine ?? "— no process command recorded on this event —"}
        </dd>
      </div>
    </dl>
  );
}
