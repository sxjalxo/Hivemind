import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ChevronRight, Code2, Rows3, ScrollText, Search, Table2 } from "lucide-react";
import { Fragment, useState } from "react";
import {
  CopyButton,
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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { isDemoMode } from "@/services";
import { formatDateTime, formatNumber } from "@/utils/format";
import { cn } from "@/lib/utils";
import type { HoneypotEvent, LogQuery, RiskLevel } from "@/types";
import { honeypotsQuery, logSearchQuery } from "@/services/queries";

interface LogSearch {
  q?: string | undefined;
  honeypot?: string | undefined;
  protocol?: string | undefined;
  category?: string | undefined;
  risk?: string | undefined;
  technique?: string | undefined;
  page?: number | undefined;
}

export const Route = createFileRoute("/logs")({
  validateSearch: (search: Record<string, unknown>): LogSearch => {
    const str = (key: string) =>
      typeof search[key] === "string" && search[key] !== "" ? (search[key] as string) : undefined;
    const page = Number(search["page"]);
    return {
      ...(str("q") ? { q: str("q") as string } : {}),
      ...(str("honeypot") ? { honeypot: str("honeypot") as string } : {}),
      ...(str("protocol") ? { protocol: str("protocol") as string } : {}),
      ...(str("category") ? { category: str("category") as string } : {}),
      ...(str("risk") ? { risk: str("risk") as string } : {}),
      ...(str("technique") ? { technique: str("technique") as string } : {}),
      ...(Number.isFinite(page) && page > 1 ? { page } : {}),
    };
  },
  component: LogExplorerPage,
});

const PAGE_SIZE = 25;

const ECS_FIELDS = [
  "timestamp",
  "source.ip",
  "destination.ip",
  "event.action",
  "event.category",
  "network.protocol",
  "user.name",
  "process.command_line",
  "honeypot.name",
  "session.id",
  "risk.score",
  "mitre.technique",
];

function LogExplorerPage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/logs" });
  const [draft, setDraft] = useState(search.q ?? "");
  const [view, setView] = useState<"table" | "json">("table");
  const [expanded, setExpanded] = useState<string | null>(null);

  const honeypots = useQuery(honeypotsQuery());

  const query: LogQuery = {
    ...(search.q ? { q: search.q } : {}),
    ...(search.honeypot ? { honeypotId: search.honeypot } : {}),
    ...(search.protocol ? { protocol: search.protocol } : {}),
    ...(search.category ? { eventCategory: search.category } : {}),
    ...(search.risk ? { risk: search.risk as RiskLevel } : {}),
    ...(search.technique ? { techniqueId: search.technique } : {}),
    page: search.page ?? 1,
    pageSize: PAGE_SIZE,
  };
  const { data, isPending, isError, error, refetch } = useQuery(logSearchQuery(query));

  const patch = (next: Partial<LogSearch>) =>
    void navigate({ search: (prev) => ({ ...prev, ...next, page: undefined }) });

  const page = search.page ?? 1;
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Log Explorer"
        subtitle="Search raw honeypot events. Fields follow Elastic Common Schema so queries map straight onto Elasticsearch."
        meta={
          <>
            <span className="label-caps">
              {isPending ? "Searching" : `${formatNumber(data?.total ?? 0)} events`}
            </span>
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
        actions={
          <div className="flex items-center gap-0.5 rounded-md border border-border bg-surface p-0.5">
            <ViewToggle
              icon={Table2}
              label="Table"
              active={view === "table"}
              onClick={() => setView("table")}
            />
            <ViewToggle
              icon={Code2}
              label="JSON"
              active={view === "json"}
              onClick={() => setView("json")}
            />
          </div>
        }
      />

      <Panel bodyClassName="p-0">
        <form
          className="border-b border-border p-3"
          onSubmit={(event) => {
            event.preventDefault();
            patch({ q: draft.trim() || undefined });
          }}
        >
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              placeholder="Search honeypot events..."
              className="h-9 pl-8 font-mono text-xs"
              aria-label="Search honeypot events"
            />
          </div>

          <div className="mt-2.5 grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-5">
            <FilterSelect
              label="Honeypot"
              value={search.honeypot}
              onChange={(value) => patch({ honeypot: value })}
              options={(honeypots.data ?? []).map((item) => ({ value: item.id, label: item.name }))}
            />
            <FilterSelect
              label="Protocol"
              value={search.protocol}
              onChange={(value) => patch({ protocol: value })}
              options={["SSH", "HTTP", "Telnet", "CAN", "SMB"].map((value) => ({
                value,
                label: value,
              }))}
            />
            <FilterSelect
              label="Event type"
              value={search.category}
              onChange={(value) => patch({ category: value })}
              options={[
                "authentication",
                "process",
                "network",
                "file",
                "session",
                "intrusion_detection",
              ].map((value) => ({ value, label: value }))}
            />
            <FilterSelect
              label="Risk"
              value={search.risk}
              onChange={(value) => patch({ risk: value })}
              options={["critical", "high", "medium", "low", "informational"].map((value) => ({
                value,
                label: value,
              }))}
            />
            <FilterSelect
              label="Technique"
              value={search.technique}
              onChange={(value) => patch({ technique: value })}
              options={["T1059", "T1078", "T1082", "T1087", "T1105", "T1222", "T1053"].map(
                (value) => ({ value, label: value }),
              )}
            />
          </div>

          <div className="mt-2.5 flex flex-wrap items-center gap-2">
            <Button type="submit" size="sm" className="h-7">
              Search
            </Button>
            <button
              type="button"
              onClick={() => {
                setDraft("");
                void navigate({ search: {} });
              }}
              className="font-mono text-[11px] uppercase tracking-[0.08em] text-muted-foreground hover:text-foreground"
            >
              Reset filters
            </button>
            <span className="ml-auto hidden font-mono text-[10px] text-muted-foreground xl:block">
              {ECS_FIELDS.join("  ")}
            </span>
          </div>
        </form>

        {isPending ? (
          <TableSkeleton rows={10} cols={6} />
        ) : isError ? (
          <ErrorState
            title={SERVICE_ERRORS.elasticsearch.title}
            description={SERVICE_ERRORS.elasticsearch.description}
            error={error}
            onRetry={() => void refetch()}
          />
        ) : data.items.length === 0 ? (
          <EmptyState
            icon={ScrollText}
            title="No honeypot events found for the selected time range."
            description="Loosen a filter or widen the search text."
          />
        ) : view === "json" ? (
          <pre className="max-h-[640px] overflow-auto p-4 font-mono text-[11px] leading-relaxed text-foreground/80">
            {JSON.stringify(
              data.items.map((item) => item.raw ?? item),
              null,
              2,
            )}
          </pre>
        ) : (
          <EventTable
            events={data.items}
            expandedId={expanded}
            onToggle={(id) => setExpanded((prev) => (prev === id ? null : id))}
          />
        )}

        {data && data.items.length > 0 ? (
          <div className="flex items-center justify-between gap-3 border-t border-border px-3 py-2.5">
            <span className="font-mono text-[11px] text-muted-foreground">
              Page {page} of {totalPages} — {formatNumber(data.total)} events
            </span>
            <span className="flex gap-1.5">
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                disabled={page <= 1}
                onClick={() =>
                  void navigate({ search: (prev) => ({ ...prev, page: page - 1 || undefined }) })
                }
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                disabled={page >= totalPages}
                onClick={() => void navigate({ search: (prev) => ({ ...prev, page: page + 1 }) })}
              >
                Next
              </Button>
            </span>
          </div>
        ) : null}
      </Panel>
    </div>
  );
}

function ViewToggle({
  icon: Icon,
  label,
  active,
  onClick,
}: {
  icon: typeof Table2;
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "flex items-center gap-1.5 rounded px-2 py-1 font-mono text-[11px] transition-colors",
        active ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground",
      )}
    >
      <Icon className="size-3.5" aria-hidden />
      {label}
    </button>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string | undefined;
  onChange: (value: string | undefined) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <Select
      value={value ?? "all"}
      onValueChange={(next) => onChange(next === "all" ? undefined : next)}
    >
      <SelectTrigger className="h-8 text-xs" aria-label={label}>
        <SelectValue placeholder={label} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all" className="text-xs">
          {label}: any
        </SelectItem>
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value} className="text-xs">
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function EventTable({
  events,
  expandedId,
  onToggle,
}: {
  events: HoneypotEvent[];
  expandedId: string | null;
  onToggle: (id: string) => void;
}) {
  return (
    <>
      <div className="hidden overflow-x-auto lg:block">
        <table className="w-full min-w-[1040px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-border">
              {[
                "",
                "@timestamp",
                "source.ip",
                "destination.ip",
                "event.action",
                "network.protocol",
                "user.name",
                "process.command_line",
                "honeypot.name",
                "mitre",
                "risk",
              ].map((heading) => (
                <th
                  key={heading}
                  className={cn(
                    "label-caps whitespace-nowrap px-2.5 py-2 text-left font-normal",
                    // Risk drives triage, so it stays pinned while the rest scrolls.
                    heading === "risk" && "sticky right-0 border-l border-border bg-card",
                  )}
                >
                  {heading}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <Fragment key={event.id}>
                <tr
                  className="group cursor-pointer border-b border-border/60 transition-colors hover:bg-accent/30"
                  onClick={() => onToggle(event.id)}
                >
                  <td className="px-2 py-2">
                    <ChevronRight
                      className={cn(
                        "size-3.5 text-muted-foreground transition-transform",
                        expandedId === event.id && "rotate-90",
                      )}
                      aria-hidden
                    />
                  </td>
                  <td className="whitespace-nowrap px-2.5 py-2">
                    <Mono tone="muted" className="text-xs">
                      {formatDateTime(event.timestamp)}
                    </Mono>
                  </td>
                  <td className="whitespace-nowrap px-2.5 py-2">
                    <Mono className="text-[13px]">{event.source.ip}</Mono>
                  </td>
                  <td className="whitespace-nowrap px-2.5 py-2">
                    <Mono tone="muted" className="text-xs">
                      {event.destination.ip}
                    </Mono>
                  </td>
                  <td className="whitespace-nowrap px-2.5 py-2 text-xs text-foreground/85">
                    {event.event.action}
                  </td>
                  <td className="whitespace-nowrap px-2.5 py-2">
                    <Mono tone="muted" className="text-xs">
                      {event.network.protocol}
                    </Mono>
                  </td>
                  <td className="whitespace-nowrap px-2.5 py-2">
                    <Mono tone="muted" className="text-xs">
                      {event.user?.name ?? "—"}
                    </Mono>
                  </td>
                  <td className="max-w-[210px] px-2.5 py-2">
                    <Mono className="block truncate text-[13px]">
                      {event.process?.commandLine ?? "—"}
                    </Mono>
                  </td>
                  <td className="whitespace-nowrap px-2.5 py-2 text-xs text-muted-foreground">
                    {event.honeypot.name}
                  </td>
                  <td className="px-2.5 py-2">
                    {event.mitre?.techniqueId ? (
                      <MitreBadge techniqueId={event.mitre.techniqueId} />
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="sticky right-0 whitespace-nowrap border-l border-border bg-card px-2.5 py-2">
                    <RiskBadge level={event.risk.level} score={event.risk.score} />
                  </td>
                </tr>
                {expandedId === event.id ? (
                  <tr className="border-b border-border/60 bg-background/50">
                    <td colSpan={11} className="p-0">
                      <EventDetail event={event} />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="divide-y divide-border/60 lg:hidden">
        {events.map((event) => (
          <li key={event.id}>
            <button
              type="button"
              onClick={() => onToggle(event.id)}
              className="w-full p-3 text-left transition-colors hover:bg-accent/30"
            >
              <span className="flex items-center justify-between gap-2">
                <Mono tone="muted" className="text-xs">
                  {formatDateTime(event.timestamp)}
                </Mono>
                <RiskBadge level={event.risk.level} score={event.risk.score} />
              </span>
              <span className="mt-1.5 block truncate font-mono text-[13px] text-foreground">
                {event.process?.commandLine ?? event.event.action}
              </span>
              <span className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-muted-foreground">
                <span>{event.source.ip}</span>
                <span>{event.network.protocol}</span>
                <span>{event.honeypot.name}</span>
                {event.mitre?.techniqueId ? <span>{event.mitre.techniqueId}</span> : null}
              </span>
            </button>
            {expandedId === event.id ? <EventDetail event={event} /> : null}
          </li>
        ))}
      </ul>
    </>
  );
}

function EventDetail({ event }: { event: HoneypotEvent }) {
  const json = JSON.stringify(event.raw ?? event, null, 2);
  return (
    <div className="grid gap-3 border-t border-border p-3 lg:grid-cols-2">
      <div>
        <p className="label-caps mb-1.5">Event fields</p>
        <dl className="space-y-1">
          {[
            ["session.id", event.session.id],
            ["event.category", event.event.category],
            ["event.outcome", event.event.outcome ?? "—"],
            ["source.port", String(event.source.port ?? "—")],
            ["destination.port", String(event.destination.port ?? "—")],
            ["risk.score", String(event.risk.score)],
            ["mitre.tactic", event.mitre?.tactic ?? "—"],
            ["ai.classification", event.aiClassification ?? "—"],
          ].map(([field, value]) => (
            <div key={field} className="flex items-baseline gap-2">
              <dt className="w-[132px] shrink-0 font-mono text-[11px] text-muted-foreground">
                {field}
              </dt>
              <dd className="min-w-0 break-all font-mono text-[12px] text-foreground/90">
                {value}
              </dd>
            </div>
          ))}
        </dl>
        <Link
          to="/sessions/$sessionId"
          params={{ sessionId: event.session.id }}
          className="mt-2.5 inline-flex items-center gap-1 font-mono text-[11px] uppercase tracking-[0.08em] text-primary hover:underline"
        >
          <Rows3 className="size-3" aria-hidden />
          Open session investigation
        </Link>
      </div>
      <div className="min-w-0">
        <div className="mb-1.5 flex items-center justify-between">
          <p className="label-caps">Raw document</p>
          <CopyButton value={json} label="Copy JSON" />
        </div>
        <pre className="max-h-56 overflow-auto rounded border border-border bg-surface/60 p-2.5 font-mono text-[11px] leading-relaxed text-foreground/80">
          {json}
        </pre>
      </div>
    </div>
  );
}
