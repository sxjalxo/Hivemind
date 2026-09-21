import { useQuery } from "@tanstack/react-query";
import { Radio } from "lucide-react";
import { AnalysisProgress } from "./AnalysisProgress";
import { DemoDataBadge, InlineNotice, StatusRow } from "@/components/common";
import { isDemoMode } from "@/services";
import { formatNumber } from "@/utils/format";
import { cn } from "@/lib/utils";
import { systemStatusQuery } from "@/services/queries";

export interface LiveMetrics {
  progressPct: number;
  eventsProcessed: number;
  commandsAnalyzed: number;
  techniquesDetected: number;
  iocsExtracted: number;
}

/**
 * Live analysis console.
 *
 * Renders whatever the backend progress channel reports. When no channel is
 * connected it says so plainly instead of animating invented counters — a fake
 * live feed would undermine the provenance model the rest of the app relies on.
 */
export function LiveAnalysisPanel({
  sessionId,
  metrics,
  stageIndex,
  active,
  className,
}: {
  sessionId?: string;
  metrics: LiveMetrics | null;
  stageIndex: number | null;
  active: boolean;
  className?: string;
}) {
  const status = useQuery(systemStatusQuery());

  return (
    <section className={cn("panel overflow-hidden", className)}>
      <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <span className="flex items-center gap-2">
          <Radio
            className={cn("size-4", active ? "text-critical pulse-dot" : "text-muted-foreground")}
            aria-hidden
          />
          <span className="font-mono text-xs uppercase tracking-[0.12em] text-foreground">
            Live analysis
          </span>
        </span>
        {isDemoMode ? <DemoDataBadge /> : null}
      </header>

      <div className="space-y-4 p-4">
        {active ? (
          <>
            <div>
              <div className="mb-2 flex items-baseline justify-between gap-2">
                <span className="text-xs text-muted-foreground">
                  {sessionId
                    ? `Receiving honeypot events for ${sessionId}`
                    : "Receiving honeypot events"}
                </span>
                <span className="font-mono text-xs tabular-nums text-foreground">
                  {metrics ? `${metrics.progressPct}%` : "--"}
                </span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                {metrics ? (
                  <div
                    className="h-full rounded-full bg-ai transition-[width] duration-500"
                    style={{ width: `${metrics.progressPct}%` }}
                  />
                ) : (
                  <div className="h-full w-1/3 rounded-full bg-ai scan-sweep" />
                )}
              </div>
            </div>

            <dl className="grid grid-cols-2 gap-2">
              {[
                { label: "Events processed", value: metrics?.eventsProcessed },
                { label: "Commands analysed", value: metrics?.commandsAnalyzed },
                { label: "Techniques detected", value: metrics?.techniquesDetected },
                { label: "IOCs extracted", value: metrics?.iocsExtracted },
              ].map((metric) => (
                <div
                  key={metric.label}
                  className="rounded-md border border-border bg-background/40 px-2.5 py-2"
                >
                  <dt className="label-caps truncate">{metric.label}</dt>
                  <dd className="mt-0.5 font-mono text-base font-semibold tabular-nums text-foreground">
                    {metric.value === undefined ? "--" : formatNumber(metric.value)}
                  </dd>
                </div>
              ))}
            </dl>

            <AnalysisProgress activeIndex={stageIndex ?? -1} />
          </>
        ) : (
          <InlineNotice tone="info" icon={Radio}>
            No analysis is currently running. Start one from a session investigation to stream
            progress here.
          </InlineNotice>
        )}

        <div className="border-t border-border pt-3">
          <p className="label-caps mb-1">Pipeline services</p>
          {(status.data ?? []).map((service) => (
            <StatusRow key={service.id} status={service} dense />
          ))}
        </div>
      </div>
    </section>
  );
}
