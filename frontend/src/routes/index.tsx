import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowRight, ShieldAlert } from "lucide-react";
import { Link } from "@tanstack/react-router";
import { ActivityTimelineChart } from "@/components/charts/ActivityTimelineChart";
import { ClassificationDonut } from "@/components/charts/ClassificationDonut";
import {
  CommandFrequencyBars,
  RiskDistributionBars,
} from "@/components/charts/RiskDistributionBars";
import { TopAttackersTable } from "@/components/dashboard/TopAttackersTable";
import {
  ClassificationChain,
  DemoDataBadge,
  EmptyState,
  ErrorState,
  KpiCard,
  KpiCardSkeleton,
  LoadingState,
  Mono,
  PageHeader,
  Panel,
  RiskBadge,
  SERVICE_ERRORS,
} from "@/components/common";
import { TimeRangeTabs } from "@/components/layout/TimeRangeSelector";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useTimeRange } from "@/hooks/useTimeRange";
import { isDemoMode } from "@/services";
import { formatDuration } from "@/utils/format";
import { dashboardQuery, sessionQueries } from "@/services/queries";

export const Route = createFileRoute("/")({
  component: DashboardPage,
});

function DashboardPage() {
  const { range, label } = useTimeRange();
  const navigate = useNavigate();
  const dashboard = useQuery(dashboardQuery(range));

  return (
    <div className="space-y-5">
      <PageHeader
        title="Honeypot Intelligence Dashboard"
        subtitle="Real-time overview of attacker activity, AI classifications and threat intelligence."
        meta={
          <>
            <span className="label-caps">Window: {label}</span>
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
        actions={
          <Button size="sm" onClick={() => void navigate({ to: "/sessions" })}>
            Triage sessions
            <ArrowRight className="size-3.5" />
          </Button>
        }
      />

      {dashboard.isError ? (
        <Panel>
          <ErrorState
            title={SERVICE_ERRORS.elasticsearch.title}
            description={SERVICE_ERRORS.elasticsearch.description}
            onRetry={() => void dashboard.refetch()}
          />
        </Panel>
      ) : (
        <>
          <section
            aria-label="Key metrics"
            className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8"
          >
            {dashboard.isPending
              ? Array.from({ length: 8 }, (_, index) => <KpiCardSkeleton key={index} />)
              : dashboard.data.kpis.map((kpi) => <KpiCard key={kpi.id} kpi={kpi} />)}
          </section>

          {/* 3/2 rather than 2/1: the classification legend needs room for full
              tactic names like "Command and Control" without truncating. */}
          <div className="grid gap-4 xl:grid-cols-5">
            <Panel
              className="xl:col-span-3"
              title="Attacker Activity Timeline"
              description="Honeypot events over the selected window, with high-risk activity overlaid."
              actions={<TimeRangeTabs />}
            >
              {dashboard.isPending ? (
                <Skeleton className="h-[248px] w-full" />
              ) : dashboard.data.timeline.length === 0 ? (
                <EmptyState
                  title="No honeypot events found for the selected time range."
                  description="Widen the window or check that sensors are shipping to Elasticsearch."
                />
              ) : (
                <ActivityTimelineChart data={dashboard.data.timeline} />
              )}
            </Panel>

            <Panel
              className="xl:col-span-2"
              title="Attack Classification"
              description="Sessions grouped by the dominant ATT&CK tactic."
            >
              {dashboard.isPending ? (
                <Skeleton className="h-[212px] w-full" />
              ) : (
                <ClassificationDonut data={dashboard.data.classifications} />
              )}
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel title="Risk Distribution" description="Sessions by assessed severity.">
              {dashboard.isPending ? (
                <Skeleton className="h-[180px] w-full" />
              ) : (
                <RiskDistributionBars
                  data={dashboard.data.riskDistribution}
                  onSelect={(level) => void navigate({ to: "/sessions", search: { risk: level } })}
                />
              )}
            </Panel>

            <Panel
              className="xl:col-span-2"
              title="Top Attacker IPs"
              description="Highest-volume sources in the selected window."
              bodyClassName="p-0 md:p-2"
            >
              {dashboard.isPending ? (
                <Skeleton className="m-4 h-[180px]" />
              ) : dashboard.data.topAttackers.length === 0 ? (
                <EmptyState title="No attacker activity in this window." />
              ) : (
                <div className="p-2 md:p-0">
                  <TopAttackersTable rows={dashboard.data.topAttackers} />
                </div>
              )}
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel
              title="Top Commands"
              description="Most frequent commands executed against the fleet."
            >
              {dashboard.isPending ? (
                <Skeleton className="h-[220px] w-full" />
              ) : (
                <CommandFrequencyBars
                  data={dashboard.data.topCommands}
                  onSelect={(command) => void navigate({ to: "/logs", search: { q: command } })}
                />
              )}
            </Panel>

            <HighRiskSessions />
          </div>
        </>
      )}
    </div>
  );
}

/** Entry point into the investigation flow: dashboard -> session investigation. */
function HighRiskSessions() {
  const { data, isPending, isError, refetch } = useQuery(sessionQueries.list());
  const highRisk = (data ?? [])
    .filter((session) => session.risk === "critical" || session.risk === "high")
    .slice(0, 6);

  return (
    <Panel
      className="xl:col-span-2"
      title="High-Risk Sessions"
      description="Start an investigation from the sessions the scorer flagged first."
      bodyClassName="p-2"
      actions={
        <Link
          to="/sessions"
          className="font-mono text-[11px] uppercase tracking-[0.08em] text-primary hover:underline"
        >
          View all
        </Link>
      }
    >
      {isPending ? (
        <LoadingState message="Loading attacker sessions..." />
      ) : isError ? (
        <ErrorState
          title={SERVICE_ERRORS.api.title}
          description={SERVICE_ERRORS.api.description}
          onRetry={() => void refetch()}
        />
      ) : highRisk.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="No high-risk sessions right now."
          description="Sessions appear here once the risk scorer rates them High or Critical."
        />
      ) : (
        <ul className="divide-y divide-border/60">
          {highRisk.map((session) => (
            <li key={session.id}>
              <Link
                to="/sessions/$sessionId"
                params={{ sessionId: session.id }}
                className="flex flex-col gap-2 rounded-md px-2 py-2.5 transition-colors hover:bg-accent/30 md:flex-row md:items-center md:gap-4"
              >
                <span className="flex min-w-0 items-center gap-2 md:w-[210px]">
                  {session.risk === "critical" ? (
                    <AlertTriangle className="size-3.5 shrink-0 text-critical" aria-hidden />
                  ) : (
                    <ShieldAlert className="size-3.5 shrink-0 text-high" aria-hidden />
                  )}
                  <Mono className="truncate text-[13px]">{session.id}</Mono>
                </span>
                <Mono tone="muted" className="text-xs md:w-[130px]">
                  {session.attackerIp}
                </Mono>
                <span className="min-w-0 flex-1">
                  <ClassificationChain chain={session.classificationChain} />
                </span>
                <span className="flex items-center gap-3">
                  <Mono tone="muted" className="text-[11px]">
                    {formatDuration(session.durationSeconds)}
                  </Mono>
                  <RiskBadge level={session.risk} score={session.riskScore} />
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
