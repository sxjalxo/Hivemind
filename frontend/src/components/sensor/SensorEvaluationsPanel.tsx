import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { FlaskConical, GitCompareArrows } from "lucide-react";
import { EmptyState, ErrorState, LoadingState, Mono, Panel } from "@/components/common";
import { ScorePill } from "@/components/evaluation/AssessmentPair";
import { RunStatusChip } from "@/components/evaluation/EvaluationStatusChips";
import { RunActor } from "@/components/evaluation/RunActor";
import { Button } from "@/components/ui/button";
import {
  CHARACTERISTIC_LABELS,
  CHARACTERISTIC_SHORT_LABELS,
  EVALUATION_CHARACTERISTICS,
  evaluationQueries,
  findScore,
  shortFingerprint,
} from "@/services/evaluation";
import { formatDateTime } from "@/utils/format";

/** One screen of this sensor's runs; the evaluation page is the full history. */
const RUN_LIMIT = 20;

/** The sensor's evaluation runs, newest first. Scores keep their two-assessment meaning. */
export function SensorEvaluationsPanel({ id }: { id: string }) {
  const { data, isPending, isError, error, refetch } = useQuery(
    evaluationQueries.list(RUN_LIMIT, id),
  );

  // Compare is offered between the two latest completed runs: a failed run has no scores to compare.
  const [head, base] = (data ?? []).filter((run) => run.status === "completed");

  return (
    <Panel
      title="Evaluations"
      description="Newest first. Deterministic scores per characteristic; the evaluator's ratings are on the run."
      actions={
        head && base ? (
          <Button variant="outline" size="sm" asChild>
            <Link to="/evaluation/compare" search={{ base: base.id, head: head.id }}>
              <GitCompareArrows className="size-3.5" />
              Compare latest two
            </Link>
          </Button>
        ) : null
      }
      bodyClassName="p-0"
    >
      {isPending ? (
        <LoadingState message="Loading evaluations..." />
      ) : isError ? (
        <ErrorState title="Evaluations unavailable" error={error} onRetry={() => void refetch()} />
      ) : data.length === 0 ? (
        <EmptyState
          icon={FlaskConical}
          title="This sensor has not been evaluated."
          description="Dispatch a run from the evaluation page."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1000px] border-collapse text-sm">
            <thead>
              <tr className="border-b border-border">
                {[
                  "Run",
                  "Started",
                  "Started by",
                  "Status",
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
              {data.map((run) => (
                <tr
                  key={run.id}
                  className="border-b border-border/60 align-top transition-colors last:border-0 hover:bg-accent/30"
                >
                  <td className="whitespace-nowrap px-3 py-2">
                    <Link
                      to="/evaluation/$runId"
                      params={{ runId: run.id }}
                      title={run.id}
                      className="font-mono text-[12px] text-foreground underline-offset-4 hover:text-primary hover:underline"
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
                    <RunStatusChip status={run.status} />
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
      )}
    </Panel>
  );
}
