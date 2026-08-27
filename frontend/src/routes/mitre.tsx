import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Grid3x3 } from "lucide-react";
import { useEffect, useState } from "react";
import { MatrixLegend, MitreMatrix } from "@/components/mitre/MitreMatrix";
import { TechniqueDrawer } from "@/components/mitre/TechniqueDrawer";
import {
  DemoDataBadge,
  EmptyState,
  ErrorState,
  InlineNotice,
  Mono,
  PageHeader,
  Panel,
} from "@/components/common";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { mitreQueries } from "@/services/mitre";
import { sessionQueries } from "@/services/sessions";
import { isDemoMode } from "@/services";
import { formatPct } from "@/utils/format";
import type { MitreTechnique } from "@/types";

interface MitreSearch {
  session?: string | undefined;
  technique?: string | undefined;
}

export const Route = createFileRoute("/mitre")({
  validateSearch: (search: Record<string, unknown>): MitreSearch => ({
    ...(typeof search["session"] === "string" ? { session: search["session"] } : {}),
    ...(typeof search["technique"] === "string" ? { technique: search["technique"] } : {}),
  }),
  component: MitrePage,
});

function MitrePage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/mitre" });
  const [selected, setSelected] = useState<MitreTechnique | null>(null);

  const sessions = useQuery(sessionQueries.list());
  const coverage = useQuery(mitreQueries.coverage(search.session));

  // Deep links such as /mitre?technique=T1059 open straight into the drawer.
  useEffect(() => {
    if (!search.technique || !coverage.data) return;
    const match = coverage.data.techniques.find((item) => item.id === search.technique);
    if (match) setSelected(match);
  }, [search.technique, coverage.data]);

  const scopeLabel = search.session ? `Session ${search.session}` : "All sessions";

  return (
    <div className="space-y-5">
      <PageHeader
        title="MITRE ATT&CK Mapping"
        subtitle="Techniques observed across honeypot telemetry, positioned on the Enterprise matrix."
        meta={
          <>
            <span className="label-caps">Scope: {scopeLabel}</span>
            {coverage.data ? (
              <span className="label-caps">
                {coverage.data.observedCount} of {coverage.data.totalCount} techniques observed
              </span>
            ) : null}
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
        actions={
          <Select
            value={search.session ?? "all"}
            onValueChange={(value) =>
              void navigate({
                search: (prev) => ({
                  ...prev,
                  ...(value === "all" ? { session: undefined } : { session: value }),
                }),
              })
            }
          >
            <SelectTrigger className="h-8 w-[230px] text-xs" aria-label="Scope by session">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all" className="text-xs">
                All sessions
              </SelectItem>
              {(sessions.data ?? []).map((session) => (
                <SelectItem key={session.id} value={session.id} className="font-mono text-xs">
                  {session.id} — {session.attackerIp}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
      />

      <InlineNotice tone="info">
        A technique is marked <strong>observed</strong> only when honeypot telemetry supports it.
        Open any technique to read the evidence behind the mapping before acting on it.
      </InlineNotice>

      <Panel
        title="Enterprise Matrix"
        description="Columns are tactics; each cell is a technique with its evidence count."
        actions={<MatrixLegend />}
      >
        {coverage.isPending ? (
          <Skeleton className="h-[420px] w-full" />
        ) : coverage.isError ? (
          <ErrorState
            title="ATT&CK coverage unavailable"
            error={coverage.error}
            onRetry={() => void coverage.refetch()}
          />
        ) : coverage.data.techniques.length === 0 ? (
          <EmptyState
            icon={Grid3x3}
            title="No ATT&CK techniques have been associated with this session."
            description="Run an AI analysis on the session to produce evidence-backed mappings."
          />
        ) : (
          <MitreMatrix
            techniques={coverage.data.techniques}
            onSelect={setSelected}
            {...(search.technique ? { highlightId: search.technique } : {})}
          />
        )}
      </Panel>

      <Panel
        title="Observed Techniques"
        description="Every mapping in scope, with the evidence that produced it."
        bodyClassName="p-0"
      >
        {coverage.isPending ? (
          <Skeleton className="m-4 h-40" />
        ) : (
          <ObservedTable
            techniques={(coverage.data?.techniques ?? []).filter((item) => item.observed)}
            onSelect={setSelected}
          />
        )}
      </Panel>

      <TechniqueDrawer
        technique={selected}
        open={selected !== null}
        onOpenChange={(open) => {
          if (open) return;
          setSelected(null);
          if (search.technique) {
            void navigate({ search: (prev) => ({ ...prev, technique: undefined }) });
          }
        }}
      />
    </div>
  );
}

function ObservedTable({
  techniques,
  onSelect,
}: {
  techniques: MitreTechnique[];
  onSelect: (technique: MitreTechnique) => void;
}) {
  if (techniques.length === 0) {
    return <EmptyState title="No techniques have been observed in this scope." />;
  }

  return (
    <>
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full min-w-[720px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-border">
              {["Technique", "Name", "Tactic", "Confidence", "Evidence", "Sessions", ""].map(
                (heading) => (
                  <th
                    key={heading}
                    className="label-caps whitespace-nowrap px-3 py-2 text-left font-normal"
                  >
                    {heading}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {techniques.map((technique) => (
              <tr
                key={technique.id}
                className="border-b border-border/60 transition-colors last:border-0 hover:bg-accent/30"
              >
                <td className="px-3 py-2">
                  <Mono className="text-[13px] text-primary">{technique.id}</Mono>
                </td>
                <td className="px-3 py-2 text-foreground/90">{technique.name}</td>
                <td className="px-3 py-2 text-xs text-muted-foreground">{technique.tactic}</td>
                <td className="px-3 py-2">
                  {technique.confidence !== undefined ? (
                    <Mono className="text-[13px]">{formatPct(technique.confidence)}</Mono>
                  ) : (
                    <span className="text-xs text-muted-foreground">n/a</span>
                  )}
                </td>
                <td className="px-3 py-2">
                  <Mono tone="muted" className="text-xs">
                    {technique.evidence.length} artefacts
                  </Mono>
                </td>
                <td className="px-3 py-2">
                  <Mono tone="muted" className="text-xs">
                    {technique.sessionCount}
                  </Mono>
                </td>
                <td className="px-3 py-2 text-right">
                  <Button variant="ghost" size="sm" onClick={() => onSelect(technique)}>
                    Evidence
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="divide-y divide-border/60 md:hidden">
        {techniques.map((technique) => (
          <li key={technique.id}>
            <button
              type="button"
              onClick={() => onSelect(technique)}
              className="w-full p-3 text-left transition-colors hover:bg-accent/30"
            >
              <span className="flex items-center justify-between gap-2">
                <Mono className="text-[13px] text-primary">{technique.id}</Mono>
                {technique.confidence !== undefined ? (
                  <Mono tone="muted" className="text-xs">
                    {formatPct(technique.confidence)}
                  </Mono>
                ) : null}
              </span>
              <span className="mt-1 block text-sm text-foreground/90">{technique.name}</span>
              <span className="mt-1 flex items-center gap-3 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                <span>{technique.tactic}</span>
                <span>{technique.evidence.length} evidence</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}
