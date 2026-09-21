import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ClipboardCopy, FileDown, FileText, Loader2, Printer, Sparkles } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { ReportView } from "@/components/report/ReportView";
import {
  DemoDataBadge,
  EmptyState,
  ErrorState,
  LoadingState,
  Mono,
  PageHeader,
  Panel,
  RiskBadge,
  SERVICE_ERRORS,
} from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAdminForSession } from "@/hooks/useAdminFor";
import { provider, isDemoMode } from "@/services";
import { formatDateTime } from "@/utils/format";
import { copyToClipboard } from "@/utils/format";
import { reportToMarkdown } from "@/utils/reportExport";
import type { ThreatReport } from "@/types";
import { reportQueries, sessionQueries } from "@/services/queries";

interface ReportSearch {
  session?: string | undefined;
  report?: string | undefined;
}

export const Route = createFileRoute("/reports")({
  validateSearch: (search: Record<string, unknown>): ReportSearch => ({
    ...(typeof search["session"] === "string" ? { session: search["session"] } : {}),
    ...(typeof search["report"] === "string" ? { report: search["report"] } : {}),
  }),
  component: ReportsPage,
});

function ReportsPage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/reports" });
  const queryClient = useQueryClient();

  const reports = useQuery(reportQueries.list());
  const sessions = useQuery(sessionQueries.list());
  const [generated, setGenerated] = useState<ThreatReport | null>(null);
  const [target, setTarget] = useState(search.session ?? "");
  // Report creation runs an analysis when the session has none, so it is an
  // admin action on the backend, scoped to the session's honeypot.
  // Presentation only -- it 403s either way.
  const canGenerate = useAdminForSession(target);

  const generate = useMutation<ThreatReport, Error, string>({
    mutationFn: (sessionId) => provider.createReport(sessionId),
    onSuccess: (report) => {
      setGenerated(report);
      void queryClient.invalidateQueries({ queryKey: ["reports"] });
      void navigate({ search: (prev) => ({ ...prev, report: report.id }) });
      toast.success("Report generated", { description: `${report.id} for ${report.sessionId}` });
    },
    onError: (error) => {
      toast.error("Report generation failed", { description: error.message });
    },
  });

  const selected = useMemo<ThreatReport | null>(() => {
    if (generated && (!search.report || generated.id === search.report)) return generated;
    const list = reports.data ?? [];
    if (search.report) return list.find((item) => item.id === search.report) ?? null;
    if (search.session) return list.find((item) => item.sessionId === search.session) ?? null;
    return list[0] ?? null;
  }, [generated, reports.data, search.report, search.session]);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Threat Reports"
        subtitle="Analyst-ready incident reports assembled from session evidence and AI interpretation."
        meta={
          <>
            <span className="label-caps">
              {reports.isPending ? "Loading" : `${reports.data?.length ?? 0} reports`}
            </span>
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
        actions={selected ? <ReportActions report={selected} /> : null}
      />

      <Panel
        title="Generate a report"
        description="Assemble a report from a session, its analysis and the extracted indicators."
      >
        <div className="flex flex-col gap-2 sm:flex-row">
          <Select value={target} onValueChange={setTarget}>
            <SelectTrigger className="h-9 flex-1 text-xs" aria-label="Session for report">
              <SelectValue placeholder="Select a session" />
            </SelectTrigger>
            <SelectContent>
              {(sessions.data ?? []).map((session) => (
                <SelectItem key={session.id} value={session.id} className="font-mono text-xs">
                  {session.id} — {session.attackerIp} — {session.risk}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            onClick={() => target && generate.mutate(target)}
            disabled={!target || generate.isPending || !canGenerate.allowed}
            title={!target ? undefined : canGenerate.title}
          >
            {generate.isPending ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <Sparkles className="size-3.5" />
            )}
            {generate.isPending ? "Generating..." : "Generate Report"}
          </Button>
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-4">
        <Panel className="xl:col-span-1" title="Saved reports" bodyClassName="p-2">
          {reports.isPending ? (
            <LoadingState message="Loading reports..." />
          ) : reports.isError ? (
            <ErrorState
              title={SERVICE_ERRORS.api.title}
              description={SERVICE_ERRORS.api.description}
              onRetry={() => void reports.refetch()}
            />
          ) : reports.data.length === 0 && !generated ? (
            <EmptyState icon={FileText} title="No reports yet." description="Generate one above." />
          ) : (
            <ul className="space-y-1">
              {[...(generated ? [generated] : []), ...(reports.data ?? [])]
                .filter(
                  (item, index, list) => list.findIndex((other) => other.id === item.id) === index,
                )
                .map((report) => (
                  <li key={report.id}>
                    <button
                      type="button"
                      onClick={() =>
                        void navigate({ search: (prev) => ({ ...prev, report: report.id }) })
                      }
                      className={`w-full rounded-md border px-2.5 py-2 text-left transition-colors ${
                        selected?.id === report.id
                          ? "border-primary/50 bg-primary/10"
                          : "border-border hover:border-border-strong hover:bg-accent/25"
                      }`}
                    >
                      <span className="flex items-center justify-between gap-2">
                        <Mono className="truncate text-[12px]">{report.id}</Mono>
                        <RiskBadge level={report.incidentOverview.risk} />
                      </span>
                      <span className="mt-1 block truncate text-xs text-foreground/85">
                        {report.title}
                      </span>
                      <span className="mt-0.5 block font-mono text-[10px] text-muted-foreground">
                        {formatDateTime(report.createdAt)}
                      </span>
                    </button>
                  </li>
                ))}
            </ul>
          )}
        </Panel>

        <Panel
          className="xl:col-span-3"
          title={selected ? selected.title : "Report"}
          description={
            selected
              ? `${selected.id} — generated by ${selected.generatedBy} on ${formatDateTime(selected.createdAt)}`
              : undefined
          }
        >
          {selected ? (
            <div id="report-print-root">
              <ReportView report={selected} />
            </div>
          ) : (
            <EmptyState
              icon={FileText}
              title="No report selected."
              description="Pick a saved report or generate a new one from a session."
            />
          )}
        </Panel>
      </div>
    </div>
  );
}

function ReportActions({ report }: { report: ThreatReport }) {
  const exportJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${report.id}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    toast.success("Report exported", { description: `${report.id}.json` });
  };

  const copy = async () => {
    if (await copyToClipboard(reportToMarkdown(report))) {
      toast.success("Report copied to clipboard");
    } else {
      toast.error("Could not access the clipboard");
    }
  };

  return (
    <>
      <Button variant="outline" size="sm" onClick={() => window.print()}>
        <Printer className="size-3.5" />
        Export PDF
      </Button>
      <Button variant="outline" size="sm" onClick={exportJson}>
        <FileDown className="size-3.5" />
        Export JSON
      </Button>
      <Button variant="outline" size="sm" onClick={() => void copy()}>
        <ClipboardCopy className="size-3.5" />
        Copy Report
      </Button>
    </>
  );
}
