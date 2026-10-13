import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { InlineNotice, Mono, ProvenanceBadge } from "@/components/common";
import { sessionQueries } from "@/services/queries";
import { formatDateTime } from "@/utils/format";

const SHOWN = 3;

/**
 * "This exact script was already analysed elsewhere" -- a pointer, never a copy.
 *
 * Reusing another session's analysis AS this session's would make every claim
 * here cite that session's log lines. So the analyst is sent to the other
 * session, whose analysis cites its own events, and decides for themselves
 * whether it describes this one -- which may save a model run.
 *
 * Renders nothing unless at least one identical session has an analysis.
 */
export function IdenticalSessionsNotice({ sessionId }: { sessionId: string }) {
  const { data } = useQuery(sessionQueries.identical(sessionId));
  if (!data || data.analysed.length === 0) return null;

  const others = data.twinCount === 1 ? "1 other session" : `${data.twinCount} other sessions`;
  return (
    <InlineNotice tone="info">
      <div className="flex flex-wrap items-center gap-2">
        <ProvenanceBadge kind="CORRELATED" />
        <span className="font-medium">
          This session ran the identical command sequence as {others}
          {data.complete ? "" : " (among the sessions examined)"}.
        </span>
      </div>
      <p className="mt-1.5 leading-relaxed">
        {data.analysed.length === 1 ? "One of them was" : `${data.analysed.length} were`} already
        analysed. Reading that analysis may save running the model here — its evidence points at its
        own session&apos;s events, not this one&apos;s.
      </p>
      <ul className="mt-2 space-y-1">
        {data.analysed.slice(0, SHOWN).map((twin) => (
          <li key={twin.analysisId} className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <Link
              to="/sessions/$sessionId"
              params={{ sessionId: twin.sessionId }}
              className="font-mono text-[12px] text-foreground underline-offset-4 hover:text-primary hover:underline"
            >
              {twin.sessionId}
            </Link>
            <span className="text-xs">{twin.classification}</span>
            <Mono tone="muted" className="text-[11px]">
              {formatDateTime(twin.createdAt)}
            </Mono>
          </li>
        ))}
      </ul>
    </InlineNotice>
  );
}
