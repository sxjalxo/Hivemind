import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ChevronRight, FlaskConical, RotateCcw } from "lucide-react";
import { useState } from "react";
import { EvaluationProgress } from "./EvaluationProgress";
import { CopyableMono, InlineNotice, Mono, Panel } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useEvaluationRun } from "@/hooks/useEvaluationRun";
import { honeypotQueries } from "@/services/honeypots";
import { EVALUATION_STAGE_COUNT, RUN_STATUS_LABELS } from "@/services/evaluation";
import { cn } from "@/lib/utils";

/**
 * Dispatches a run and follows it.
 *
 * `POST /api/evaluations` answers 202 with only a run id — no scores, no
 * findings, nothing measured. This panel therefore never presents the POST's
 * response as a result: it shows the id, follows the progress channel where one
 * exists, and reads the outcome back from `GET /api/evaluations/{runId}`, which
 * is the authoritative record.
 *
 * The run needs a honeypot to run against, so the target is chosen here from
 * the registry the backend resolves ids through.
 */
export function RunEvaluationPanel() {
  const honeypots = useQuery(honeypotQueries.list());
  const [target, setTarget] = useState<string>("");
  const { runId, phase, progress, run, dispatchError, startFailure, isBusy, start, reset } =
    useEvaluationRun();

  return (
    <Panel
      title="Run an evaluation"
      description="Pick a honeypot to evaluate. The request is accepted, not awaited — the backend answers with a run id and works in the background."
      actions={
        runId !== null || phase === "dispatch_failed" ? (
          <Button variant="outline" size="sm" onClick={reset} disabled={isBusy}>
            <RotateCcw className="size-3.5" />
            Clear
          </Button>
        ) : null
      }
    >
      <div className="flex flex-col gap-2 sm:flex-row">
        <Select value={target} onValueChange={setTarget}>
          <SelectTrigger className="h-9 flex-1 text-xs" aria-label="Honeypot to evaluate">
            <SelectValue
              placeholder={honeypots.isPending ? "Loading honeypots..." : "Select a honeypot"}
            />
          </SelectTrigger>
          <SelectContent>
            {(honeypots.data ?? []).map((honeypot) => (
              <SelectItem key={honeypot.id} value={honeypot.id} className="text-xs">
                {honeypot.name} — {honeypot.id} ({honeypot.status})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          size="sm"
          className="h-9"
          disabled={target === "" || isBusy}
          onClick={() => start(target)}
        >
          <FlaskConical className={cn("size-3.5", isBusy && "animate-pulse")} aria-hidden />
          {isBusy ? "Evaluation in flight..." : "Run evaluation"}
        </Button>
      </div>

      {honeypots.isError ? (
        <InlineNotice tone="critical" className="mt-3">
          The honeypot registry could not be read, so there is no target to evaluate against.
        </InlineNotice>
      ) : null}

      {phase === "dispatch_failed" ? (
        <InlineNotice tone="critical" className="mt-3">
          <p className="font-medium">The run was not accepted.</p>
          <p className="mt-1 font-mono text-[11px] leading-relaxed">
            {dispatchError?.message ?? "The backend refused the request."}
          </p>
          <p className="mt-1 leading-relaxed">
            A 409 means an evaluation is already running for that honeypot; a 404 means the id is
            not in the registry. No run was dispatched, so there is no run id to follow.
          </p>
        </InlineNotice>
      ) : null}

      {runId !== null ? (
        <div className="mt-4 space-y-3 border-t border-border pt-3.5">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="label-caps">Run id</span>
            <CopyableMono value={runId} className="text-[12px]" />
            <span className="label-caps ml-auto">{PHASE_LABEL[phase]}</span>
          </div>

          {phase === "start_failed" ? (
            <InlineNotice tone="critical">
              <p className="font-medium">The run failed before it had a record.</p>
              <p className="mt-1 whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed">
                {startFailure}
              </p>
              <p className="mt-1 leading-relaxed">
                Nothing was measured and no run row exists, so{" "}
                <Mono className="text-[11px]">GET /api/evaluations/{runId}</Mono> will 404
                permanently. This message is the only record of the failure.
              </p>
            </InlineNotice>
          ) : run !== null && (run.status === "completed" || run.status === "failed") ? (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
              <span className="text-xs text-muted-foreground">
                The run is {RUN_STATUS_LABELS[run.status].toLowerCase()} and its record is
                authoritative.
              </span>
              <Link
                to="/evaluation/$runId"
                params={{ runId }}
                className="inline-flex items-center gap-1 font-mono text-[11px] uppercase tracking-[0.08em] text-primary hover:underline"
              >
                Open the run
                <ChevronRight className="size-3" aria-hidden />
              </Link>
            </div>
          ) : (
            <RunningView
              indeterminate={progress.indeterminate}
              hasChannel={progress.hasChannel}
              stageIndex={progress.stageIndex}
              progressPct={progress.metrics?.progressPct ?? null}
              metrics={progress.metrics}
              waitingForRecord={phase === "waiting_for_record"}
            />
          )}
        </div>
      ) : null}
    </Panel>
  );
}

const PHASE_LABEL: Record<string, string> = {
  idle: "Idle",
  dispatching: "Dispatching",
  dispatch_failed: "Refused",
  waiting_for_record: "Accepted — no record yet",
  running: "Running",
  settled: "Settled",
  start_failed: "Failed to start",
};

function RunningView({
  indeterminate,
  hasChannel,
  stageIndex,
  progressPct,
  metrics,
  waitingForRecord,
}: {
  indeterminate: boolean;
  hasChannel: boolean;
  stageIndex: number | null;
  progressPct: number | null;
  metrics: {
    probesExecuted: number | null;
    chainStepsVerified: number | null;
    characteristicsScored: number | null;
    characteristicsEvaluated: number | null;
  } | null;
  waitingForRecord: boolean;
}) {
  return (
    <div className="grid gap-5 md:grid-cols-2">
      <div>
        <div className="mb-3 h-1 overflow-hidden rounded-full bg-muted">
          {indeterminate || progressPct === null ? (
            <div className="scan-sweep h-full w-1/3 rounded-full bg-ai" />
          ) : (
            <div
              className="h-full rounded-full bg-ai transition-[width] duration-500"
              style={{ width: `${Math.max(0, Math.min(100, progressPct))}%` }}
            />
          )}
        </div>

        <EvaluationProgress activeIndex={stageIndex} />

        <p className="mt-3 border-t border-border pt-2.5 text-[11px] leading-relaxed text-muted-foreground">
          {!hasChannel
            ? `This data source publishes no progress channel, so these ${EVALUATION_STAGE_COUNT} stages show the expected pipeline rather than live status.`
            : indeterminate
              ? `No stage frame has arrived yet. The channel has no replay, so frames published before this page subscribed are gone — the run may already be past these ${EVALUATION_STAGE_COUNT} stages.`
              : "Stages are live from the run's progress channel."}
          {waitingForRecord
            ? " The run record has not appeared yet; the outcome is read from the authoritative GET, not from this channel."
            : null}
        </p>
      </div>

      <dl className="grid grid-cols-2 gap-2 self-start">
        {[
          { label: "Probes executed", value: metrics?.probesExecuted ?? null },
          { label: "Chain steps verified", value: metrics?.chainStepsVerified ?? null },
          { label: "Characteristics scored", value: metrics?.characteristicsScored ?? null },
          { label: "Characteristics evaluated", value: metrics?.characteristicsEvaluated ?? null },
        ].map((metric) => (
          <div
            key={metric.label}
            className="rounded-md border border-border bg-background/40 p-2.5"
          >
            <dt className="label-caps truncate">{metric.label}</dt>
            <dd className="mt-1 font-mono text-lg font-semibold tabular-nums text-foreground">
              {metric.value ?? "--"}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
