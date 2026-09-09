import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ScorePill } from "@/components/evaluation/AssessmentPair";
import {
  DemoDataBadge,
  ErrorState,
  InlineNotice,
  LoadingState,
  Mono,
  PageHeader,
  Panel,
  SERVICE_ERRORS,
} from "@/components/common";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  EVALUATION_CHARACTERISTICS,
  NO_COMPOSITE_NOTE,
  SCORE_SCALE_NOTE,
  characteristicLabel,
  evaluationQueries,
  findScore,
  formatDeltaPp,
  shortFingerprint,
} from "@/services/evaluation";
import { isDemoMode } from "@/services";
import { formatDateTime } from "@/utils/format";
import type {
  EvaluationCategoryScore,
  EvaluationRun,
  EvaluationRunSummary,
  RunComparison,
} from "@/types";

interface CompareSearch {
  base?: string | undefined;
  head?: string | undefined;
}

export const Route = createFileRoute("/evaluation/compare")({
  validateSearch: (search: Record<string, unknown>): CompareSearch => ({
    ...(typeof search["base"] === "string" ? { base: search["base"] } : {}),
    ...(typeof search["head"] === "string" ? { head: search["head"] } : {}),
  }),
  component: CompareRunsPage,
});

function CompareRunsPage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/evaluation/compare" });
  const history = useQuery(evaluationQueries.list(50));

  const base = search.base ?? "";
  const head = search.head ?? "";
  const ready = base !== "" && head !== "";

  const comparison = useQuery({
    ...evaluationQueries.compare(base, head),
    enabled: ready,
  });

  return (
    <div className="space-y-5">
      <PageHeader
        title="Compare evaluation runs"
        subtitle="What moved between two runs, and whether the move is attributable to the honeypot at all."
        meta={isDemoMode ? <DemoDataBadge /> : null}
      />

      <InlineNotice tone="info">
        {SCORE_SCALE_NOTE} Deltas are in percentage points of the deterministic assessment.{" "}
        {NO_COMPOSITE_NOTE}
      </InlineNotice>

      <Panel
        title="Pick two runs"
        description="Base is the earlier state; head is the state you are testing against it."
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <RunPicker
            label="Base run"
            value={base}
            runs={history.data ?? []}
            loading={history.isPending}
            onChange={(value) =>
              void navigate({ search: (previous) => ({ ...previous, base: value }) })
            }
          />
          <RunPicker
            label="Head run"
            value={head}
            runs={history.data ?? []}
            loading={history.isPending}
            onChange={(value) =>
              void navigate({ search: (previous) => ({ ...previous, head: value }) })
            }
          />
        </div>
        {history.isError ? (
          <InlineNotice tone="critical" className="mt-3">
            The run history could not be read, so there is nothing to pick from.
          </InlineNotice>
        ) : null}
        {ready && base === head ? (
          <InlineNotice tone="warn" className="mt-3">
            Base and head are the same run, so every delta is zero by construction.
          </InlineNotice>
        ) : null}
      </Panel>

      {!ready ? (
        <Panel>
          <p className="py-8 text-center text-sm text-muted-foreground">
            Pick a base and a head run to see the deltas.
          </p>
        </Panel>
      ) : comparison.isPending ? (
        <LoadingState message="Comparing runs..." />
      ) : comparison.isError ? (
        <Panel>
          <ErrorState
            title="Comparison unavailable"
            error={comparison.error}
            description={SERVICE_ERRORS.api.description}
            onRetry={() => void comparison.refetch()}
          />
        </Panel>
      ) : (
        <ComparisonView comparison={comparison.data} />
      )}
    </div>
  );
}

function RunPicker({
  label,
  value,
  runs,
  loading,
  onChange,
}: {
  label: string;
  value: string;
  runs: EvaluationRunSummary[];
  loading: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <div>
      <p className="label-caps mb-1.5">{label}</p>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger className="h-9 w-full text-xs" aria-label={label}>
          <SelectValue placeholder={loading ? "Loading runs..." : "Select a run"} />
        </SelectTrigger>
        <SelectContent>
          {runs.map((run) => (
            <SelectItem key={run.id} value={run.id} className="text-xs">
              {run.id.slice(0, 8)} — {run.honeypotId} — {formatDateTime(run.startedAt)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

/**
 * `classification` is `configuration_changed` when EITHER fingerprint moved,
 * and the two mean opposite things — so this view never renders that single
 * flag as one verdict.
 *
 * A changed `honeypotFingerprint` is the POINT of the comparison: the honeypot
 * changed, and that change is the improvement being measured. A changed
 * `evaluationConfigFingerprint` is what actually undermines attribution: our
 * own probes, chains, rulebook or budget moved, so the two runs asked the
 * honeypot different questions. The comparison is never refused either way.
 */
function ComparisonView({ comparison }: { comparison: RunComparison }) {
  const tokens = new Set(
    comparison.differences.map((item) => item.replace(/[^a-z0-9]/gi, "").toLowerCase()),
  );
  // Derived from the fingerprints themselves as well as `differences`, because
  // the two are spelled differently by different data sources.
  const honeypotChanged =
    comparison.base.honeypotFingerprint !== comparison.head.honeypotFingerprint ||
    tokens.has("honeypotfingerprint");
  const configChanged =
    comparison.base.evaluationConfigFingerprint !== comparison.head.evaluationConfigFingerprint ||
    tokens.has("evaluationconfigfingerprint");

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        {honeypotChanged ? (
          <InlineNotice tone="info">
            <p className="font-medium">The honeypot changed between these runs.</p>
            <p className="mt-1 leading-relaxed">
              This is what the comparison is for. The honeypot fingerprint covers the image and
              cowrie.cfg, so a different one means the thing being measured was modified — the
              deltas below are the effect of that modification.
            </p>
          </InlineNotice>
        ) : (
          <InlineNotice tone="info">
            <p className="font-medium">The honeypot did not change between these runs.</p>
            <p className="mt-1 leading-relaxed">
              Same image and cowrie.cfg on both sides, so any delta below is run-to-run variation of
              the same honeypot rather than the effect of a change to it.
            </p>
          </InlineNotice>
        )}

        {configChanged ? (
          <InlineNotice tone="warn">
            <p className="font-medium">
              The evaluation configuration changed — deltas are not attributable to the honeypot.
            </p>
            <p className="mt-1 leading-relaxed">
              The evaluation config fingerprint covers our probes, chains, rulebook and agent
              budget. A different one means the two runs asked the honeypot different questions, so
              a moved score may be our change rather than the honeypot&apos;s. The comparison is
              still shown in full — read it as two measurements, not as one trend.
            </p>
          </InlineNotice>
        ) : (
          <InlineNotice tone="info">
            <p className="font-medium">The evaluation configuration is identical.</p>
            <p className="mt-1 leading-relaxed">
              Same probes, chains, rulebook and agent budget on both sides, so both runs asked the
              honeypot the same questions and a delta is attributable to what changed in the
              honeypot.
            </p>
          </InlineNotice>
        )}
      </div>

      <Panel title="Runs" bodyClassName="p-0">
        <div className="grid gap-0 sm:grid-cols-2 sm:divide-x sm:divide-border">
          <RunSummaryCard label="Base" run={comparison.base} />
          <RunSummaryCard label="Head" run={comparison.head} />
        </div>
        <div className="border-t border-border px-4 py-2.5">
          <span className="label-caps mr-2">Backend classification</span>
          <Mono tone="muted" className="text-[11px]">
            {comparison.classification}
          </Mono>
          {comparison.differences.length > 0 ? (
            <>
              <span className="label-caps ml-3 mr-2">Differences</span>
              <Mono tone="muted" className="text-[11px]">
                {comparison.differences.join(", ")}
              </Mono>
            </>
          ) : null}
        </div>
      </Panel>

      <Panel
        title="Deterministic assessment deltas"
        description="head − base, in percentage points. The evaluator rating is never deltaed and never merged in; both sides are shown as they are."
        bodyClassName="p-0"
      >
        <DeltaTable comparison={comparison} />
      </Panel>
    </div>
  );
}

function RunSummaryCard({ label, run }: { label: string; run: EvaluationRun }) {
  return (
    <div className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="label-caps">{label}</span>
        <Link
          to="/evaluation/$runId"
          params={{ runId: run.id }}
          className="font-mono text-[12px] underline-offset-4 hover:text-primary hover:underline"
          title={run.id}
        >
          {run.id.slice(0, 8)}
        </Link>
      </div>
      <dl className="mt-2 space-y-1.5">
        <Row label="Honeypot" value={run.honeypotId} />
        <Row label="Started" value={formatDateTime(run.startedAt)} />
        <Row label="Status" value={run.status} />
        <Row label="Evaluator" value={run.evaluatorStatus} />
        <Row
          label="Honeypot fp"
          value={shortFingerprint(run.honeypotFingerprint)}
          title={run.honeypotFingerprint}
        />
        <Row
          label="Config fp"
          value={shortFingerprint(run.evaluationConfigFingerprint)}
          title={run.evaluationConfigFingerprint}
        />
      </dl>
    </div>
  );
}

function Row({ label, value, title }: { label: string; value: string; title?: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="label-caps">{label}</dt>
      <dd className="min-w-0 truncate" title={title ?? value}>
        <Mono tone="muted" className="text-[11px]">
          {value}
        </Mono>
      </dd>
    </div>
  );
}

/**
 * A null delta from the payload is AMBIGUOUS: it means either "not established
 * on one side" or "not measured in this run" (a run that replayed no chains
 * omits `attack_possibilities` entirely). The payload cannot tell them apart —
 * membership in each side's `categoryScores` can, and does, below.
 */
function DeltaTable({ comparison }: { comparison: RunComparison }) {
  const seen = new Set<string>([
    ...comparison.base.categoryScores.map((score) => score.characteristic),
    ...comparison.head.categoryScores.map((score) => score.characteristic),
    ...Object.keys(comparison.deltas),
  ]);
  const known: string[] = EVALUATION_CHARACTERISTICS.filter((characteristic) =>
    seen.has(characteristic),
  );
  // A characteristic the backend added since this build is still rendered,
  // under its raw key rather than dropped from the comparison.
  const extra = [...seen].filter((characteristic) => !known.includes(characteristic));
  const rows: string[] = [...known, ...extra];

  if (rows.length === 0) {
    return (
      <p className="p-4 text-xs text-muted-foreground">
        Neither run scored any characteristic, so there is nothing to compare.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[860px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border">
            {[
              "Characteristic",
              "Base deterministic",
              "Head deterministic",
              "Delta",
              "Base evaluator",
              "Head evaluator",
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
          {rows.map((characteristic) => {
            const baseScore = findScore(comparison.base, characteristic);
            const headScore = findScore(comparison.head, characteristic);
            const delta = comparison.deltas[characteristic] ?? null;

            return (
              <tr key={characteristic} className="border-b border-border/60 last:border-0">
                <td className="whitespace-nowrap px-3 py-2 text-xs text-foreground/85">
                  {characteristicLabel(characteristic)}
                </td>
                <td className="px-3 py-2">
                  <ScorePill
                    value={baseScore?.deterministicScore ?? null}
                    absent={baseScore === undefined}
                  />
                </td>
                <td className="px-3 py-2">
                  <ScorePill
                    value={headScore?.deterministicScore ?? null}
                    absent={headScore === undefined}
                  />
                </td>
                <td className="px-3 py-2">
                  <DeltaCell base={baseScore} head={headScore} delta={delta} />
                </td>
                <td className="px-3 py-2">
                  <ScorePill
                    value={baseScore?.evaluatorRating ?? null}
                    absent={baseScore === undefined}
                  />
                </td>
                <td className="px-3 py-2">
                  <ScorePill
                    value={headScore?.evaluatorRating ?? null}
                    absent={headScore === undefined}
                  />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DeltaCell({
  base,
  head,
  delta,
}: {
  base: EvaluationCategoryScore | undefined;
  head: EvaluationCategoryScore | undefined;
  delta: number | null;
}) {
  // "Not measured" and "not established" are different absences, and the
  // comparison payload alone cannot distinguish them. Membership does.
  if (base === undefined || head === undefined) {
    const side =
      base === undefined && head === undefined
        ? "either run"
        : base === undefined
          ? "the base run"
          : "the head run";
    return (
      <span
        title="The characteristic is absent from that run's categoryScores: the run never measured it, so there is no value to subtract."
        className="font-mono text-[11px] italic text-muted-foreground/70"
      >
        not measured in {side}
      </span>
    );
  }

  if (delta === null) {
    const side =
      base.deterministicScore === null && head.deterministicScore === null
        ? "either run"
        : base.deterministicScore === null
          ? "the base run"
          : "the head run";
    return (
      <span
        title="The characteristic was measured but nothing was established on one side, so there is no delta. A delta against 'not established' is not a delta, and is never rendered as 0."
        className="font-mono text-[11px] italic text-muted-foreground"
      >
        not established in {side}
      </span>
    );
  }

  const rounded = Math.round(delta * 100);
  return (
    <span
      className={
        rounded > 0
          ? "font-mono text-[12px] font-semibold tabular-nums text-success"
          : rounded < 0
            ? "font-mono text-[12px] font-semibold tabular-nums text-high"
            : "font-mono text-[12px] font-semibold tabular-nums text-muted-foreground"
      }
    >
      {formatDeltaPp(delta)}
    </span>
  );
}
