import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Radar, Server } from "lucide-react";
import {
  DemoDataBadge,
  EmptyState,
  ErrorState,
  Mono,
  PageHeader,
  Panel,
  RiskBadge,
  SERVICE_ERRORS,
  StatusDot,
} from "@/components/common";
import { Skeleton } from "@/components/ui/skeleton";
import { isDemoMode } from "@/services";
import { formatDateTime, formatNumber } from "@/utils/format";
import { cn } from "@/lib/utils";
import type { Honeypot, HoneypotStatus } from "@/types";
import { honeypotQueries } from "@/services/queries";

export const Route = createFileRoute("/honeypots")({
  component: HoneypotsPage,
});

const STATUS_STATE: Record<HoneypotStatus, "connected" | "degraded" | "disconnected"> = {
  online: "connected",
  degraded: "degraded",
  offline: "disconnected",
};

const STATUS_TEXT: Record<HoneypotStatus, string> = {
  online: "text-success",
  degraded: "text-medium",
  offline: "text-critical",
};

function HoneypotsPage() {
  const { data, isPending, isError, error, refetch } = useQuery(honeypotQueries.list());

  const online = (data ?? []).filter((item) => item.status === "online").length;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Honeypots"
        subtitle="Deployed sensors, their interaction level and the traffic they are currently absorbing."
        meta={
          <>
            <span className="label-caps">
              {isPending ? "Loading" : `${online} of ${data?.length ?? 0} online`}
            </span>
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
      />

      {isPending ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }, (_, index) => (
            <Skeleton key={index} className="h-[190px] w-full rounded-xl" />
          ))}
        </div>
      ) : isError ? (
        <Panel>
          <ErrorState
            title={SERVICE_ERRORS.api.title}
            description={SERVICE_ERRORS.api.description}
            error={error}
            onRetry={() => void refetch()}
          />
        </Panel>
      ) : data.length === 0 ? (
        <Panel>
          <EmptyState
            icon={Radar}
            title="No honeypots are registered."
            description="Register a sensor with the backend for it to appear here."
          />
        </Panel>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {data.map((honeypot) => (
              <HoneypotCard key={honeypot.id} honeypot={honeypot} />
            ))}
          </div>

          <Panel title="Fleet Detail" bodyClassName="p-0" className="hidden lg:flex">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[900px] border-collapse text-sm">
                <thead>
                  <tr className="border-b border-border">
                    {[
                      "Name",
                      "Type",
                      "OS",
                      "Interaction",
                      "IP",
                      "Status",
                      "Active",
                      "Events",
                      "Last activity",
                      "Risk",
                    ].map((heading) => (
                      <th
                        key={heading}
                        className="label-caps whitespace-nowrap px-3 py-2 text-left font-normal"
                      >
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.map((honeypot) => (
                    <tr
                      key={honeypot.id}
                      className="border-b border-border/60 transition-colors last:border-0 hover:bg-accent/30"
                    >
                      <td className="whitespace-nowrap px-3 py-2 font-medium text-foreground">
                        {honeypot.name}
                      </td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{honeypot.type}</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{honeypot.os}</td>
                      <td className="px-3 py-2 text-xs capitalize text-muted-foreground">
                        {honeypot.interactionLevel}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">
                        <Mono className="text-[13px]">{honeypot.ip}</Mono>
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">
                        <span className="flex items-center gap-1.5">
                          <StatusDot state={STATUS_STATE[honeypot.status]} />
                          <span
                            className={cn(
                              "font-mono text-[10px] uppercase tracking-[0.08em]",
                              STATUS_TEXT[honeypot.status],
                            )}
                          >
                            {honeypot.status}
                          </span>
                        </span>
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
                        {honeypot.activeSessions}
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
                        {formatNumber(honeypot.events)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">
                        <Mono tone="muted" className="text-xs">
                          {formatDateTime(honeypot.lastActivity)}
                        </Mono>
                      </td>
                      <td className="px-3 py-2">
                        <RiskBadge level={honeypot.risk} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}

function HoneypotCard({ honeypot }: { honeypot: Honeypot }) {
  return (
    <article className="panel flex flex-col p-4">
      <header className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="flex size-8 shrink-0 items-center justify-center rounded-md border border-border bg-muted/40">
            <Server className="size-4 text-muted-foreground" aria-hidden />
          </span>
          <div className="min-w-0">
            <h3 className="truncate text-sm font-semibold text-foreground">{honeypot.name}</h3>
            <p className="font-mono text-[11px] text-muted-foreground">{honeypot.ip}</p>
          </div>
        </div>
        <RiskBadge level={honeypot.risk} />
      </header>

      <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2.5">
        <Detail label="Type" value={honeypot.type} />
        <Detail label="Interaction" value={honeypot.interactionLevel} capitalize />
        <Detail label="Operating system" value={honeypot.os} />
        <Detail label="Status">
          <span className="flex items-center gap-1.5">
            <StatusDot state={STATUS_STATE[honeypot.status]} />
            <span
              className={cn(
                "font-mono text-[11px] uppercase tracking-[0.08em]",
                STATUS_TEXT[honeypot.status],
              )}
            >
              {honeypot.status}
            </span>
          </span>
        </Detail>
      </dl>

      <div className="mt-4 grid grid-cols-3 gap-2 border-t border-border pt-3">
        <Metric label="Active" value={String(honeypot.activeSessions)} />
        <Metric label="Events" value={formatNumber(honeypot.events)} />
        <Metric label="Last seen" value={formatDateTime(honeypot.lastActivity).slice(11)} />
      </div>

      <Link
        to="/sessions"
        search={{ q: honeypot.name }}
        className="mt-3 font-mono text-[11px] uppercase tracking-[0.08em] text-primary hover:underline"
      >
        View sessions
      </Link>
    </article>
  );
}

function Detail({
  label,
  value,
  children,
  capitalize,
}: {
  label: string;
  value?: string;
  children?: React.ReactNode;
  capitalize?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="label-caps">{label}</dt>
      <dd className={cn("mt-0.5 truncate text-xs text-foreground/90", capitalize && "capitalize")}>
        {children ?? value}
      </dd>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <p className="label-caps truncate">{label}</p>
      <p className="mt-0.5 font-mono text-sm font-semibold tabular-nums text-foreground">{value}</p>
    </div>
  );
}
