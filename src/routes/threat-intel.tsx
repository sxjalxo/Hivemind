import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  FileDigit,
  Fingerprint,
  Globe,
  Link2,
  Network,
  Search,
  ShieldAlert,
  TerminalSquare,
  UserRound,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  ConfidenceBar,
  CopyButton,
  DemoDataBadge,
  EmptyState,
  ErrorState,
  Mono,
  PageHeader,
  Panel,
  ProvenanceBadge,
  SERVICE_ERRORS,
  TableSkeleton,
} from "@/components/common";
import { Input } from "@/components/ui/input";
import { threatIntelQueries } from "@/services/threatIntel";
import { isDemoMode } from "@/services";
import { formatDateTime } from "@/utils/format";
import { cn } from "@/lib/utils";
import type { Indicator, IndicatorType } from "@/types";

interface IntelSearch {
  q?: string | undefined;
  type?: string | undefined;
}

export const Route = createFileRoute("/threat-intel")({
  validateSearch: (search: Record<string, unknown>): IntelSearch => ({
    ...(typeof search["q"] === "string" ? { q: search["q"] } : {}),
    ...(typeof search["type"] === "string" ? { type: search["type"] } : {}),
  }),
  component: ThreatIntelPage,
});

const TYPE_META: Record<IndicatorType, { label: string; icon: typeof Globe }> = {
  ip: { label: "IP addresses", icon: Network },
  domain: { label: "Domains", icon: Globe },
  url: { label: "URLs", icon: Link2 },
  hash: { label: "File hashes", icon: Fingerprint },
  username: { label: "Usernames", icon: UserRound },
  filename: { label: "File names", icon: FileDigit },
  command: { label: "Commands", icon: TerminalSquare },
};

const TYPE_ORDER: IndicatorType[] = [
  "ip",
  "domain",
  "url",
  "hash",
  "username",
  "filename",
  "command",
];

function ThreatIntelPage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/threat-intel" });
  const [query, setQuery] = useState(search.q ?? "");

  const activeType = search.type;
  const params = {
    ...(activeType ? { type: activeType } : {}),
    ...(query.trim() ? { q: query.trim() } : {}),
  };
  const { data, isPending, isError, error, refetch } = useQuery(
    threatIntelQueries.indicators(params),
  );

  // Counts come from the unfiltered set so the type rail never collapses to zero.
  const all = useQuery(threatIntelQueries.indicators());
  const counts = useMemo(() => {
    const tally = Object.fromEntries(TYPE_ORDER.map((type) => [type, 0])) as Record<
      IndicatorType,
      number
    >;
    for (const indicator of all.data ?? []) tally[indicator.type] += 1;
    return tally;
  }, [all.data]);

  const setType = (type: string | undefined) =>
    void navigate({ search: (prev) => ({ ...prev, type }) });

  return (
    <div className="space-y-5">
      <PageHeader
        title="Threat Intelligence"
        subtitle="Indicators extracted from honeypot sessions, with the provenance of each one."
        meta={
          <>
            <span className="label-caps">
              {isPending ? "Loading" : `${data?.length ?? 0} indicators`}
            </span>
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
      />

      <section
        aria-label="Indicator types"
        className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-7"
      >
        {TYPE_ORDER.map((type) => {
          const meta = TYPE_META[type];
          const active = activeType === type;
          return (
            <button
              key={type}
              type="button"
              onClick={() => setType(active ? undefined : type)}
              aria-pressed={active}
              className={cn(
                "panel flex items-center gap-2.5 px-3 py-2.5 text-left transition-colors",
                active
                  ? "border-primary/50 bg-primary/10"
                  : "hover:border-border-strong hover:bg-accent/25",
              )}
            >
              <meta.icon
                className={cn("size-4 shrink-0", active ? "text-primary" : "text-muted-foreground")}
                aria-hidden
              />
              <span className="min-w-0">
                <span className="block truncate text-[11px] text-muted-foreground">
                  {meta.label}
                </span>
                <span className="block font-mono text-base font-semibold tabular-nums text-foreground">
                  {counts[type]}
                </span>
              </span>
            </button>
          );
        })}
      </section>

      <Panel
        title="Indicators of Compromise"
        description="Filter by type or search across values and tags."
        bodyClassName="p-0"
        actions={
          activeType ? (
            <button
              type="button"
              onClick={() => setType(undefined)}
              className="font-mono text-[11px] uppercase tracking-[0.08em] text-primary hover:underline"
            >
              Clear filter
            </button>
          ) : null
        }
      >
        <div className="border-b border-border p-3">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search indicators by value or tag"
              className="h-8 pl-8 font-mono text-xs"
              aria-label="Search indicators"
            />
          </div>
        </div>

        {isPending ? (
          <TableSkeleton rows={8} cols={6} />
        ) : isError ? (
          <ErrorState
            title={SERVICE_ERRORS.api.title}
            description={SERVICE_ERRORS.api.description}
            error={error}
            onRetry={() => void refetch()}
          />
        ) : data.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="No indicators match these filters."
            description="Clear the search or pick a different indicator type."
          />
        ) : (
          <IndicatorTable indicators={data} />
        )}
      </Panel>
    </div>
  );
}

function IndicatorTable({ indicators }: { indicators: Indicator[] }) {
  return (
    <>
      <div className="hidden overflow-x-auto lg:block">
        <table className="w-full min-w-[900px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-border">
              {[
                "Type",
                "Indicator",
                "Confidence",
                "Source",
                "First seen",
                "Last seen",
                "Sessions",
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
            {indicators.map((indicator) => (
              <tr
                key={indicator.id}
                className="group border-b border-border/60 transition-colors last:border-0 hover:bg-accent/30"
              >
                <td className="whitespace-nowrap px-3 py-2">
                  <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                    {indicator.type}
                  </span>
                </td>
                <td className="max-w-[320px] px-3 py-2">
                  <span className="flex items-center gap-1">
                    <Mono className="truncate text-[13px]">{indicator.value}</Mono>
                    <CopyButton
                      value={indicator.value}
                      className="opacity-0 group-hover:opacity-100 focus:opacity-100"
                    />
                  </span>
                  {indicator.tags.length > 0 ? (
                    <span className="mt-1 flex flex-wrap gap-1">
                      {indicator.tags.map((tag) => (
                        <span
                          key={tag}
                          className="rounded border border-border bg-muted/40 px-1 py-px font-mono text-[9px] text-muted-foreground"
                        >
                          {tag}
                        </span>
                      ))}
                    </span>
                  ) : null}
                </td>
                <td className="w-[132px] px-3 py-2">
                  <ConfidenceBar value={indicator.confidence} compact />
                </td>
                <td className="px-3 py-2">
                  <ProvenanceBadge kind={indicator.source} showIcon={false} />
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <Mono tone="muted" className="text-xs">
                    {formatDateTime(indicator.firstSeen)}
                  </Mono>
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <Mono tone="muted" className="text-xs">
                    {formatDateTime(indicator.lastSeen)}
                  </Mono>
                </td>
                <td className="px-3 py-2">
                  <span className="flex flex-wrap gap-1">
                    {indicator.sessionIds.map((sessionId) => (
                      <Link
                        key={sessionId}
                        to="/sessions/$sessionId"
                        params={{ sessionId }}
                        className="font-mono text-[10px] text-primary hover:underline"
                      >
                        {sessionId}
                      </Link>
                    ))}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="divide-y divide-border/60 lg:hidden">
        {indicators.map((indicator) => (
          <li key={indicator.id} className="p-3">
            <div className="flex items-start justify-between gap-2">
              <Mono className="min-w-0 break-all text-[13px]">{indicator.value}</Mono>
              <CopyButton value={indicator.value} />
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                {indicator.type}
              </span>
              <ProvenanceBadge kind={indicator.source} showIcon={false} />
            </div>
            <div className="mt-2">
              <ConfidenceBar value={indicator.confidence} compact />
            </div>
            <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10px] text-muted-foreground">
              <span>First {formatDateTime(indicator.firstSeen)}</span>
              <span>Last {formatDateTime(indicator.lastSeen)}</span>
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}
