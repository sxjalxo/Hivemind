import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { FlaskConical, GitCompareArrows } from "lucide-react";
import { ScorePill } from "@/components/evaluation/AssessmentPair";
import { EvaluatorStatusChip, RunStatusChip } from "@/components/evaluation/EvaluationStatusChips";
import { RunActor } from "@/components/evaluation/RunActor";
import { RunEvaluationPanel } from "@/components/evaluation/RunEvaluationPanel";
import {
  DemoDataBadge,
  EmptyState,
  ErrorState,
  InlineNotice,
  Mono,
  PageHeader,
  Panel,
  SERVICE_ERRORS,
  TableSkeleton,
} from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  CHARACTERISTIC_LABELS,
  CHARACTERISTIC_SHORT_LABELS,
  EVALUATION_CHARACTERISTICS,
  NO_COMPOSITE_NOTE,
  SCORE_SCALE_NOTE,
  evaluationQueries,
  findScore,
  shortFingerprint,
} from "@/services/evaluation";
import { isDemoMode } from "@/services";
import { formatDateTime } from "@/utils/format";
import type { EvaluationRunSummary } from "@/types";

export const Route = createFileRoute("/evaluation/")({
  component: EvaluationHistoryPage,
});

/** One screen of history. The backend caps `limit` at 100 (101+ is a 422). */
const HISTORY_LIMIT = 50;

function EvaluationHistoryPage() {
  const { data, isPending, isError, refetch } = useQuery(evaluationQueries.list(HISTORY_LIMIT));

  return (
    <div className="space-y-5">
      <PageHeader
        title="Honeypot Realism Evaluation"
        subtitle="How convincing the honeypot itself looks to an attacker, measured two ways that are never combined."
        meta={
          <>
            <span className="label-caps">
              {isPending ? "Loading" : `${data?.length ?? 0} runs`}
            </span>
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/evaluation/compare">
              <GitCompareArrows className="size-3.5" />
              Compare runs
            </Link>
          </Button>
        }
      />

      <InlineNotice tone="info">
        {SCORE_SCALE_NOTE} {NO_COMPOSITE_NOTE} A null is rendered as words, never as 0 — it means we
        could not establish the fact, not that the honeypot failed it.
      </InlineNotice>

      <RunEvaluationPanel />

      <Panel
        title="Run history"
        description="Newest first. A summary row carries scores only — findings, modules, chain steps and probe results live on the run itself."
        bodyClassName="p-0"
      >
        {isPending ? (
          <TableSkeleton rows={6} cols={7} />
        ) : isError ? (
          <ErrorState
            title={SERVICE_ERRORS.api.title}
            description={SERVICE_ERRORS.api.description}
            onRetry={() => void refetch()}
          />
        ) : data.length === 0 ? (
          <EmptyState
            icon={FlaskConical}
            title="No evaluation runs yet."
            description="Dispatch a run against a honeypot above. The request is accepted immediately and the run works in the background."
          />
        ) : (
          <HistoryTable runs={data} />
        )}
      </Panel>
    </div>
  );
}

function HistoryTable({ runs }: { runs: EvaluationRunSummary[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[1320px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border">
            {[
              "Run",
              "Started",
              "Started by",
              "Finished",
              "Honeypot",
              "Status",
              "Evaluator",
              "Honeypot fingerprint",
              "Evaluation config fingerprint",
              "Deterministic assessment per characteristic",
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
          {runs.map((run) => (
            <tr
              key={run.id}
              className="border-b border-border/60 align-top transition-colors last:border-0 hover:bg-accent/30"
            >
              <td className="whitespace-nowrap px-3 py-2">
                <Link
                  to="/evaluation/$runId"
                  params={{ runId: run.id }}
                  className="font-mono text-[12px] text-foreground underline-offset-4 hover:text-primary hover:underline"
                  title={run.id}
                >
                  {run.id.slice(0, 8)}
                </Link>
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <Mono tone="muted" className="text-[11px]">
                  {formatDateTime(run.startedAt)}
                </Mono>
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <RunActor startedBy={run.startedBy} startedByLabel={run.startedByLabel} />
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                {run.finishedAt ? (
                  <Mono tone="muted" className="text-[11px]">
                    {formatDateTime(run.finishedAt)}
                  </Mono>
                ) : (
                  <span className="font-mono text-[11px] italic text-muted-foreground">
                    not finished
                  </span>
                )}
              </td>
              <td className="whitespace-nowrap px-3 py-2 text-xs text-foreground/85">
                {run.honeypotId}
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <RunStatusChip status={run.status} />
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <EvaluatorStatusChip status={run.evaluatorStatus} model={run.evaluatorModel} />
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <span title={run.honeypotFingerprint}>
                  <Mono tone="muted" className="text-[11px]">
                    {shortFingerprint(run.honeypotFingerprint)}
                  </Mono>
                </span>
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <span title={run.evaluationConfigFingerprint}>
                  <Mono tone="muted" className="text-[11px]">
                    {shortFingerprint(run.evaluationConfigFingerprint)}
                  </Mono>
                </span>
              </td>
              <td className="px-3 py-2">
                <div className="flex flex-wrap gap-x-3 gap-y-1">
                  {EVALUATION_CHARACTERISTICS.map((characteristic) => {
                    const score = findScore(run, characteristic);
                    return (
                      <span
                        key={characteristic}
                        className="inline-flex min-w-[74px] flex-col gap-0.5"
                        title={CHARACTERISTIC_LABELS[characteristic]}
                      >
                        <span className="label-caps">
                          {CHARACTERISTIC_SHORT_LABELS[characteristic]}
                        </span>
                        <ScorePill
                          value={score?.deterministicScore ?? null}
                          absent={score === undefined}
                        />
                      </span>
                    );
                  })}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
