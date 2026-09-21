import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Bot, Sparkles } from "lucide-react";
import { useState } from "react";
import { AnalysisStateChip } from "@/components/session/AnalysisStateChip";
import { LiveAnalysisPanel } from "@/components/session/LiveAnalysisPanel";
import {
  ConfidenceBar,
  DemoDataBadge,
  EmptyState,
  ErrorState,
  Mono,
  PageHeader,
  Panel,
  RiskBadge,
  SERVICE_ERRORS,
  TableSkeleton,
} from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAnalysisRun } from "@/hooks/useAnalysisRun";
import { useAdminForSession } from "@/hooks/useAdminFor";
import { analysisQueries } from "@/services/analysis";
import { sessionQueries } from "@/services/sessions";
import { isDemoMode } from "@/services";
import { formatDateTime } from "@/utils/format";
import type { AnalysisState, SessionAnalysis } from "@/types";

export const Route = createFileRoute("/analysis")({
  component: AnalysisPage,
});

const STATUS_TO_CHIP: Record<SessionAnalysis["status"], AnalysisState> = {
  queued: "queued",
  running: "analyzing",
  completed: "completed",
  failed: "failed",
};

function AnalysisPage() {
  const history = useQuery(analysisQueries.history());
  const sessions = useQuery(sessionQueries.list());
  const navigate = useNavigate();

  const [target, setTarget] = useState<string>("");
  const { isRunning, run, analyze, analysis } = useAnalysisRun(target);
  // Roles are per-honeypot and a session belongs to one, so this resolves
  // the selected session to its honeypot rather than asking the coarser
  // "admin anywhere" question the backend only uses as a pre-filter.
  const canAnalyze = useAdminForSession(target);

  return (
    <div className="space-y-5">
      <PageHeader
        title="AI Analysis"
        subtitle="Every analysis run against honeypot sessions, with the model and timing reported by the backend."
        meta={
          <>
            <span className="label-caps">
              {history.isPending ? "Loading" : `${history.data?.length ?? 0} runs`}
            </span>
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          className="xl:col-span-2"
          title="Run an analysis"
          description="Pick a session to send through the analysis pipeline."
        >
          <div className="flex flex-col gap-2 sm:flex-row">
            <Select value={target} onValueChange={setTarget}>
              <SelectTrigger className="h-9 flex-1 text-xs" aria-label="Session to analyse">
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
              onClick={analyze}
              disabled={!target || isRunning || !canAnalyze.allowed}
              title={!target ? undefined : canAnalyze.title}
              className="bg-ai text-ai-foreground hover:bg-ai/90"
            >
              <Sparkles className="size-3.5" />
              {isRunning ? "Analysing..." : "AI Analyze"}
            </Button>
          </div>

          {analysis ? (
            <div className="mt-4 rounded-md border border-ai/30 bg-ai/[0.05] p-3">
              <p className="text-sm text-foreground">
                Analysis <Mono className="text-[13px]">{analysis.id}</Mono> completed:{" "}
                {analysis.classification}
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-2.5"
                onClick={() =>
                  void navigate({
                    to: "/sessions/$sessionId",
                    params: { sessionId: analysis.sessionId },
                  })
                }
              >
                Open investigation
              </Button>
            </div>
          ) : null}

          <p className="mt-4 border-t border-border pt-3 text-[11px] leading-relaxed text-muted-foreground">
            The model, analysis type and duration shown throughout this page are reported by the
            backend for each run; the UI does not assume a particular LLM.
          </p>
        </Panel>

        <LiveAnalysisPanel
          {...(target ? { sessionId: target } : {})}
          active={isRunning}
          metrics={run.metrics}
          stageIndex={run.stageIndex}
        />
      </div>

      <Panel
        title="Analysis History"
        description="Completed and failed runs, newest first."
        bodyClassName="p-0"
      >
        {history.isPending ? (
          <TableSkeleton rows={8} cols={7} />
        ) : history.isError ? (
          <ErrorState
            title={SERVICE_ERRORS.ai.title}
            description={SERVICE_ERRORS.ai.description}
            error={history.error}
            onRetry={() => void history.refetch()}
          />
        ) : history.data.length === 0 ? (
          <EmptyState
            icon={Bot}
            title="No analyses have been run yet."
            description="Analyse a session to populate this history."
          />
        ) : (
          <HistoryTable analyses={history.data} />
        )}
      </Panel>
    </div>
  );
}

function HistoryTable({ analyses }: { analyses: SessionAnalysis[] }) {
  return (
    <>
      <div className="hidden overflow-x-auto lg:block">
        <table className="w-full min-w-[940px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-border">
              {[
                "Analysis ID",
                "Session",
                "Model",
                "Analysis type",
                "Status",
                "Confidence",
                "Risk",
                "Created",
                "Duration",
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
            {analyses.map((analysis) => (
              <tr
                key={analysis.id}
                className="border-b border-border/60 transition-colors last:border-0 hover:bg-accent/30"
              >
                <td className="whitespace-nowrap px-3 py-2">
                  <Mono className="text-[13px]">{analysis.id}</Mono>
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <Link
                    to="/sessions/$sessionId"
                    params={{ sessionId: analysis.sessionId }}
                    className="font-mono text-[13px] text-foreground underline-offset-4 hover:text-primary hover:underline"
                  >
                    {analysis.sessionId}
                  </Link>
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <Mono tone="muted" className="text-xs">
                    {analysis.model}
                  </Mono>
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-xs text-foreground/85">
                  {analysis.analysisType}
                </td>
                <td className="px-3 py-2">
                  <AnalysisStateChip state={STATUS_TO_CHIP[analysis.status]} />
                </td>
                <td className="w-[128px] px-3 py-2">
                  <ConfidenceBar value={analysis.confidence} compact />
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <RiskBadge level={analysis.risk} score={analysis.riskScore} />
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <Mono tone="muted" className="text-xs">
                    {formatDateTime(analysis.createdAt)}
                  </Mono>
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <Mono tone="muted" className="text-xs">
                    {analysis.durationSeconds.toFixed(1)}s
                  </Mono>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="divide-y divide-border/60 lg:hidden">
        {analyses.map((analysis) => (
          <li key={analysis.id} className="p-3">
            <div className="flex items-center justify-between gap-2">
              <Mono className="text-[13px]">{analysis.id}</Mono>
              <RiskBadge level={analysis.risk} score={analysis.riskScore} />
            </div>
            <Link
              to="/sessions/$sessionId"
              params={{ sessionId: analysis.sessionId }}
              className="mt-1 block font-mono text-xs text-primary hover:underline"
            >
              {analysis.sessionId}
            </Link>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <AnalysisStateChip state={STATUS_TO_CHIP[analysis.status]} />
              <Mono tone="muted" className="text-[11px]">
                {analysis.model}
              </Mono>
              <Mono tone="muted" className="text-[11px]">
                {analysis.durationSeconds.toFixed(1)}s
              </Mono>
            </div>
            <div className="mt-2">
              <ConfidenceBar value={analysis.confidence} compact />
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}
