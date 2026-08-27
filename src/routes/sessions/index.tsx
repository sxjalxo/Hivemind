import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Activity, Search } from "lucide-react";
import { useState } from "react";
import {
  ClassificationChain,
  DemoDataBadge,
  EmptyState,
  ErrorState,
  MitreBadge,
  Mono,
  PageHeader,
  Panel,
  RiskBadge,
  SERVICE_ERRORS,
  TableSkeleton,
} from "@/components/common";
import { AnalysisStateChip } from "@/components/session/AnalysisStateChip";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { sessionQueries } from "@/services/sessions";
import { isDemoMode } from "@/services";
import { cn } from "@/lib/utils";
import { formatDateTime, formatDuration } from "@/utils/format";
import type { AttackSession, RiskLevel } from "@/types";

interface SessionSearch {
  risk?: string | undefined;
  q?: string | undefined;
}

export const Route = createFileRoute("/sessions/")({
  validateSearch: (search: Record<string, unknown>): SessionSearch => ({
    ...(typeof search["risk"] === "string" ? { risk: search["risk"] } : {}),
    ...(typeof search["q"] === "string" ? { q: search["q"] } : {}),
  }),
  component: SessionsPage,
});

const RISK_OPTIONS: { value: string; label: string }[] = [
  { value: "all", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "informational", label: "Informational" },
];

function SessionsPage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/sessions/" });
  const [query, setQuery] = useState(search.q ?? "");

  const risk = search.risk ?? "all";
  const params = {
    ...(risk !== "all" ? { risk } : {}),
    ...(query.trim() ? { q: query.trim() } : {}),
  };
  const { data, isPending, isError, refetch } = useQuery(sessionQueries.list(params));

  return (
    <div className="space-y-5">
      <PageHeader
        title="Attack Sessions"
        subtitle="Every attacker session captured by the honeypot fleet, ranked for triage."
        meta={
          <>
            <span className="label-caps">
              {isPending ? "Loading" : `${data?.length ?? 0} sessions`}
            </span>
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
      />

      <Panel bodyClassName="p-0">
        <div className="flex flex-col gap-2 border-b border-border p-3 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Filter by session ID, attacker IP, honeypot or technique"
              className="h-8 pl-8 font-mono text-xs"
              aria-label="Filter sessions"
            />
          </div>
          <Select
            value={risk}
            onValueChange={(value) =>
              void navigate({
                search: (prev) => ({
                  ...prev,
                  ...(value === "all" ? { risk: undefined } : { risk: value }),
                }),
              })
            }
          >
            <SelectTrigger className="h-8 w-full text-xs sm:w-[168px]" aria-label="Severity filter">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {RISK_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value} className="text-xs">
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {isPending ? (
          <TableSkeleton rows={8} cols={6} />
        ) : isError ? (
          <ErrorState
            title={SERVICE_ERRORS.api.title}
            description={SERVICE_ERRORS.api.description}
            onRetry={() => void refetch()}
          />
        ) : data.length === 0 ? (
          <EmptyState
            icon={Activity}
            title="No attacker sessions match these filters."
            description="Clear the search or widen the severity filter to see more sessions."
          />
        ) : (
          <SessionsTable sessions={data} />
        )}
      </Panel>
    </div>
  );
}

export function SessionsTable({ sessions }: { sessions: AttackSession[] }) {
  return (
    <>
      <div className="hidden overflow-x-auto lg:block">
        <table className="w-full min-w-[1040px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-border">
              {[
                "Session",
                "Attacker",
                "Ports",
                "Honeypot",
                "Proto",
                "Started",
                "Duration",
                "Cmds",
                "Classification",
                "Techniques",
                "AI",
                "Risk",
              ].map((heading) => (
                <th
                  key={heading}
                  className={cn(
                    "label-caps whitespace-nowrap px-3 py-2 text-left font-normal",
                    // Risk drives triage, so it stays pinned while the rest scrolls.
                    heading === "Risk" && "sticky right-0 border-l border-border bg-card",
                  )}
                >
                  {heading}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sessions.map((session) => (
              <SessionRow key={session.id} session={session} />
            ))}
          </tbody>
        </table>
      </div>

      <ul className="divide-y divide-border/60 lg:hidden">
        {sessions.map((session) => (
          <li key={session.id}>
            <Link
              to="/sessions/$sessionId"
              params={{ sessionId: session.id }}
              className="block p-3 transition-colors hover:bg-accent/30"
            >
              <div className="flex items-center justify-between gap-2">
                <Mono className="truncate text-[13px]">{session.id}</Mono>
                <RiskBadge level={session.risk} score={session.riskScore} />
              </div>
              <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                <Mono tone="muted" className="text-xs">
                  {session.attackerIp}
                </Mono>
                <span>{session.protocol}</span>
                <span>{session.honeypotName}</span>
                <span>{formatDuration(session.durationSeconds)}</span>
                <span>{session.commandCount} cmds</span>
              </div>
              <div className="mt-2">
                <ClassificationChain chain={session.classificationChain} />
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1">
                {session.mitreTechniqueIds.slice(0, 4).map((id) => (
                  <MitreBadge key={id} techniqueId={id} />
                ))}
                {session.mitreTechniqueIds.length > 4 ? (
                  <span className="font-mono text-[10px] text-muted-foreground">
                    +{session.mitreTechniqueIds.length - 4}
                  </span>
                ) : null}
                <AnalysisStateChip state={session.analysisState} className="ml-auto" />
              </div>
            </Link>
          </li>
        ))}
      </ul>
    </>
  );
}

function SessionRow({ session }: { session: AttackSession }) {
  const risk: RiskLevel = session.risk;
  return (
    <tr className="border-b border-border/60 transition-colors last:border-0 hover:bg-accent/30">
      <td className="whitespace-nowrap px-3 py-2">
        <Link
          to="/sessions/$sessionId"
          params={{ sessionId: session.id }}
          className="font-mono text-[13px] text-foreground underline-offset-4 hover:text-primary hover:underline"
        >
          {session.id}
        </Link>
      </td>
      <td className="whitespace-nowrap px-3 py-2">
        <Link
          to="/attackers/$ip"
          params={{ ip: session.attackerIp }}
          className="font-mono text-[13px] text-foreground/90 underline-offset-4 hover:text-primary hover:underline"
        >
          {session.attackerIp}
        </Link>
      </td>
      <td className="whitespace-nowrap px-3 py-2">
        <Mono tone="muted" className="text-xs">
          {session.sourcePort} &rarr; {session.destinationPort}
        </Mono>
      </td>
      <td className="whitespace-nowrap px-3 py-2 text-xs text-foreground/85">
        {session.honeypotName}
      </td>
      <td className="whitespace-nowrap px-3 py-2">
        <Mono tone="muted" className="text-xs">
          {session.protocol}
        </Mono>
      </td>
      <td className="whitespace-nowrap px-3 py-2">
        <Mono tone="muted" className="text-xs">
          {formatDateTime(session.startedAt)}
        </Mono>
      </td>
      <td className="whitespace-nowrap px-3 py-2">
        <Mono tone="muted" className="text-xs">
          {formatDuration(session.durationSeconds)}
        </Mono>
      </td>
      <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
        {session.commandCount}
      </td>
      <td className="max-w-[220px] px-3 py-2">
        <ClassificationChain chain={session.classificationChain} />
      </td>
      <td className="px-3 py-2">
        <span className="flex flex-wrap items-center gap-1">
          {session.mitreTechniqueIds.slice(0, 3).map((id) => (
            <MitreBadge key={id} techniqueId={id} />
          ))}
          {session.mitreTechniqueIds.length > 3 ? (
            <span className="font-mono text-[10px] text-muted-foreground">
              +{session.mitreTechniqueIds.length - 3}
            </span>
          ) : null}
        </span>
      </td>
      <td className="px-3 py-2">
        <AnalysisStateChip state={session.analysisState} />
      </td>
      <td className="sticky right-0 whitespace-nowrap border-l border-border bg-card px-3 py-2">
        <RiskBadge level={risk} score={session.riskScore} />
      </td>
    </tr>
  );
}
