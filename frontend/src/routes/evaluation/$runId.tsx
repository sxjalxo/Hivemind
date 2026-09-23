import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, GitCompareArrows } from "lucide-react";
import { useEffect, useState } from "react";
import { AssessmentPair } from "@/components/evaluation/AssessmentPair";
import { EvaluatorStatusChip, RunStatusChip } from "@/components/evaluation/EvaluationStatusChips";
import { EvaluationFindings } from "@/components/evaluation/EvaluationFindings";
import {
  ChainStepTable,
  ModuleResultTable,
  ProbeResultTable,
} from "@/components/evaluation/EvaluationTables";
import {
  CopyableMono,
  DemoDataBadge,
  EmptyState,
  ErrorState,
  InlineNotice,
  LoadingState,
  Mono,
  PageHeader,
  Panel,
  SERVICE_ERRORS,
} from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  CHARACTERISTIC_LABELS,
  EVALUATION_CHARACTERISTICS,
  EVALUATION_POLL_MS,
  EVALUATION_RECORD_GRACE_MS,
  NO_COMPOSITE_NOTE,
  RUN_EVALUATOR_ABSENCE_TEXT,
  SCORE_SCALE_NOTE,
  evaluationQueries,
  findScore,
  isSettledRun,
} from "@/services/evaluation";
import { isDemoMode } from "@/services";
import { formatDateTime } from "@/utils/format";
import type { EvaluationRun } from "@/types";

export const Route = createFileRoute("/evaluation/$runId")({
  component: EvaluationRunPage,
});

function EvaluationRunPage() {
  const { runId } = Route.useParams();

  // A 404 here is NOT always "not yet started". A run that died before its row
  // existed 404s permanently, so the wait for a record is bounded: after the
  // grace window the page says the run has no record rather than spinning.
  const [waitingSince] = useState(() => Date.now());
  const [gaveUpWaiting, setGaveUpWaiting] = useState(false);

  const query = useQuery({
    ...evaluationQueries.detail(runId),
    refetchInterval: (running) => {
      const run = running.state.data;
      if (run === undefined) return EVALUATION_POLL_MS;
      if (run === null) return gaveUpWaiting ? false : EVALUATION_POLL_MS;
      return isSettledRun(run) ? false : EVALUATION_POLL_MS;
    },
  });

  useEffect(() => {
    if (query.data !== null) return;
    const remaining = waitingSince + EVALUATION_RECORD_GRACE_MS - Date.now();
    if (remaining <= 0) {
      setGaveUpWaiting(true);
      return;
    }
    const timer = window.setTimeout(() => setGaveUpWaiting(true), remaining);
    return () => window.clearTimeout(timer);
  }, [query.data, waitingSince]);

  if (query.isPending) return <LoadingState message="Loading evaluation run..." />;

  if (query.isError) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Panel>
          <ErrorState
            title="Evaluation run unavailable"
            error={query.error}
            description={SERVICE_ERRORS.api.description}
            onRetry={() => void query.refetch()}
          />
        </Panel>
      </div>
    );
  }

  if (query.data === null) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Panel>
          <EmptyState
            title={gaveUpWaiting ? "This run has no record." : "Waiting for the run record..."}
            description={
              gaveUpWaiting
                ? "The backend has no row for this run id. Either the id is wrong, or the run aborted before its row was inserted — the container reset or a fingerprint failed — in which case this id 404s permanently and the only record of the failure was the terminal frame on its progress channel."
                : "The run was dispatched but its row has not been written yet. This page reads the authoritative record rather than waiting on the progress channel, which has no replay."
            }
          />
        </Panel>
      </div>
    );
  }

  return <RunDetail run={query.data} />;
}

function RunDetail({ run }: { run: EvaluationRun }) {
  const evaluatorAbsence =
    run.evaluatorStatus === "completed" ? null : RUN_EVALUATOR_ABSENCE_TEXT[run.evaluatorStatus];
  const everyModuleCompleted =
    run.modules.length > 0 && run.modules.every((module) => module.moduleStatus === "completed");
  const measured = new Set(run.categoryScores.map((score) => score.characteristic));
  const unmeasured = EVALUATION_CHARACTERISTICS.filter(
    (characteristic) => !measured.has(characteristic),
  );

  return (
    <div className="space-y-5">
      <BackLink />

      <PageHeader
        title={`Evaluation run ${run.id.slice(0, 8)}`}
        subtitle={`Honeypot ${run.honeypotId}, started ${formatDateTime(run.startedAt)}${
          run.finishedAt ? `, finished ${formatDateTime(run.finishedAt)}` : ", not yet finished"
        }.`}
        meta={
          <>
            <RunStatusChip status={run.status} />
            <EvaluatorStatusChip status={run.evaluatorStatus} model={run.evaluatorModel} />
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/evaluation/compare" search={{ head: run.id }}>
              <GitCompareArrows className="size-3.5" />
              Compare
            </Link>
          </Button>
        }
      />

      {run.status === "failed" ? (
        <InlineNotice tone="warn">
          <p className="font-medium">This run failed. The honeypot did not.</p>
          <p className="mt-1 leading-relaxed">
            A failed status means OUR orchestration failed
            {everyModuleCompleted ? ", and every module below reported completed" : ""}. The modules
            measured what they measured and those measurements stand as recorded; nothing here is a
            verdict against the honeypot.
          </p>
        </InlineNotice>
      ) : null}

      {evaluatorAbsence ? (
        <InlineNotice tone="info">
          <p className="font-medium">{evaluatorAbsence}</p>
          <p className="mt-1 leading-relaxed">
            Every evaluator rating on this run is therefore absent. Absent is not zero: the
            deterministic assessment below stands on its own and is not adjusted to compensate.
          </p>
        </InlineNotice>
      ) : null}

      <Panel title="Provenance" bodyClassName="p-4">
        <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Run id">
            <CopyableMono value={run.id} className="text-[12px]" />
          </Field>
          <Field label="Honeypot">
            <Mono className="text-[12px]">{run.honeypotId}</Mono>
          </Field>
          <Field
            label="Agent"
            hint="Not a model name: the probe agent is deterministic, so no model drives it."
          >
            <Mono className="text-[12px]">{run.agentModel}</Mono>
          </Field>
          <Field label="Evaluator model">
            {run.evaluatorModel ? (
              <Mono className="text-[12px]">{run.evaluatorModel}</Mono>
            ) : (
              <span className="font-mono text-[12px] italic text-muted-foreground">
                no evaluator model — the evaluator never ran
              </span>
            )}
          </Field>
          <Field
            label="Honeypot fingerprint"
            hint="What the honeypot was: its image and cowrie.cfg."
          >
            <CopyableMono value={run.honeypotFingerprint} className="text-[11px] break-all" />
          </Field>
          <Field
            label="Evaluation config fingerprint"
            hint="What we asked it: probes, chains, rulebook, agent budget."
          >
            <CopyableMono
              value={run.evaluationConfigFingerprint}
              className="text-[11px] break-all"
            />
          </Field>
        </dl>
      </Panel>

      <Panel
        title="Assessments per characteristic"
        description={`${SCORE_SCALE_NOTE} ${NO_COMPOSITE_NOTE}`}
      >
        {run.categoryScores.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            This run scored no characteristics at all.
          </p>
        ) : (
          <div className="grid gap-3 lg:grid-cols-2">
            {run.categoryScores.map((score) => (
              <AssessmentPair key={score.characteristic} score={score} />
            ))}
          </div>
        )}

        {unmeasured.length > 0 ? (
          <p className="mt-3 border-t border-border pt-2.5 text-[11px] leading-relaxed text-muted-foreground">
            Not measured by this run:{" "}
            <span className="text-foreground/80">
              {unmeasured.map((item) => CHARACTERISTIC_LABELS[item]).join(", ")}
            </span>
            . An absent characteristic is not a null one — the run never asked the question, so
            there is no answer either way.
          </p>
        ) : null}
      </Panel>

      <Panel
        title="Modules"
        description="A module's status is not a fact's status: a module that stopped early leaves facts unknown, and unknown is excluded from scoring rather than counted against the honeypot."
      >
        <ModuleResultTable modules={run.modules} />
      </Panel>

      <Panel
        title="Findings"
        description="Grouped by characteristic. Every finding carries the evidence it rests on."
      >
        <EvaluationFindings run={run} />
      </Panel>

      <Panel
        title="Chain steps"
        description="Expected technique → command → Cowrie event → matched rule. Expand an event id to read the event the honeypot actually recorded."
        bodyClassName="p-0"
      >
        <div className="p-3">
          <ChainStepTable steps={run.chainSteps} />
        </div>
      </Panel>

      <Panel
        title="Probe results"
        description="What each deterministic probe established, and the ids a finding's probe citation resolves against."
        bodyClassName="p-0"
      >
        <div className="p-3">
          <ProbeResultTable probes={run.probeResults} />
        </div>
      </Panel>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="min-w-0">
      <dt className="label-caps" title={hint}>
        {label}
      </dt>
      <dd className="mt-1 min-w-0">{children}</dd>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/evaluation"
      className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-[0.08em] text-muted-foreground transition-colors hover:text-foreground"
    >
      <ArrowLeft className="size-3.5" aria-hidden />
      Evaluation runs
    </Link>
  );
}
