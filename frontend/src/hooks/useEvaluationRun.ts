import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import { provider } from "@/services";
import {
  EVALUATION_POLL_MS,
  EVALUATION_RECORD_GRACE_MS,
  evaluationQueries,
  isSettledRun,
} from "@/services/evaluation";
import { isEvaluationFailure } from "@/types";
import type {
  EvaluationProgressEvent,
  EvaluationRun,
  EvaluationStageIndex,
  LiveEvaluationMetrics,
} from "@/types";

/**
 * Drives one evaluation run from dispatch to authoritative result.
 *
 * The flow the backend actually implements, and the reason this hook is not a
 * single mutation: `POST /api/evaluations` answers 202 with ONLY a run id. The
 * run has not happened. So:
 *
 *   POST -> take runId -> subscribe to the progress channel on that exact id
 *        -> poll GET /api/evaluations/{runId} for the authoritative record.
 *
 * Three failure shapes are handled distinctly.
 *
 *  * The POST itself is refused (409 already running, 404 unknown honeypot, or
 *    the backend is down). There is no run id and nothing to watch.
 *  * The run is dispatched and then dies BEFORE its row exists -- the container
 *    reset or either fingerprint aborts. That exception reaches no HTTP caller,
 *    so the router publishes one terminal frame (`stage: "failed"`,
 *    `stageIndex: -1`, `metrics: null`, `error: "<Type>: <message>"`) and
 *    nothing else. That frame is the ONLY record of the failure, and the GET
 *    404s permanently. `isEvaluationFailure` narrows it before anything touches
 *    `stageIndex` or `metrics`, because `EVALUATION_STAGES[-1]` is `undefined`
 *    and `metrics.progressPct` would throw.
 *  * The same death, but the terminal frame was missed (no channel, or the
 *    frame was published before the socket connected -- there is no replay).
 *    Then only the permanent 404 is visible, so the wait is BOUNDED: after
 *    EVALUATION_RECORD_GRACE_MS with no row the run is reported as failed to
 *    start rather than spun on forever.
 *
 * The progress channel is decoration. It has no replay and no completion
 * frame, and `subscribeEvaluationProgress` is optional on `DataProvider` (the
 * demo provider omits it), so nothing here is gated on a frame arriving: the
 * poll settles the run on its own.
 */

export interface EvaluationRunProgress {
  /** Live stage, or null when no stage frame has been received. */
  stageIndex: EvaluationStageIndex | null;
  metrics: LiveEvaluationMetrics | null;
  /**
   * True when progress is genuinely unknown rather than merely at stage 0 --
   * either the provider offers no channel, or frames published before we
   * subscribed were lost (the channel has no replay).
   */
  indeterminate: boolean;
  /** Whether the provider exposes a progress channel at all. */
  hasChannel: boolean;
}

export type EvaluationRunPhase =
  /** Nothing dispatched yet. */
  | "idle"
  /** The POST is in flight. */
  | "dispatching"
  /** The POST was refused; there is no run id. */
  | "dispatch_failed"
  /** 202 received, but no run row has appeared yet. */
  | "waiting_for_record"
  /** A run row exists and the run is still moving. */
  | "running"
  /** The run row is completed or failed; the record is authoritative. */
  | "settled"
  /** The run died before its row existed. There will never be a record. */
  | "start_failed";

const NO_PROGRESS: EvaluationRunProgress = {
  stageIndex: null,
  metrics: null,
  indeterminate: true,
  hasChannel: false,
};

export function useEvaluationRun() {
  const queryClient = useQueryClient();
  const [runId, setRunId] = useState<string | null>(null);
  const [dispatchedAt, setDispatchedAt] = useState<number | null>(null);
  const [progress, setProgress] = useState<EvaluationRunProgress>(NO_PROGRESS);
  /** The terminal frame's error text -- the only record of a pre-row failure. */
  const [failureFrame, setFailureFrame] = useState<string | null>(null);
  const [graceExpired, setGraceExpired] = useState(false);

  const mutation = useMutation<{ runId: string }, Error, string>({
    mutationFn: (honeypotId: string) => provider.startEvaluation(honeypotId),
    onMutate: () => {
      setRunId(null);
      setDispatchedAt(null);
      setFailureFrame(null);
      setGraceExpired(false);
      setProgress({
        stageIndex: null,
        metrics: null,
        indeterminate: true,
        hasChannel: Boolean(provider.subscribeEvaluationProgress),
      });
    },
    onSuccess: (response) => {
      // 202 Accepted. This is a channel key and a GET target, not a result.
      setRunId(response.runId);
      setDispatchedAt(Date.now());
    },
  });

  const runQuery = useQuery({
    ...evaluationQueries.detail(runId ?? ""),
    // A received terminal frame is final: the row will never exist, so stop
    // asking for it.
    enabled: runId !== null && failureFrame === null,
    refetchInterval: (query) => {
      const run = query.state.data;
      if (run === undefined) return EVALUATION_POLL_MS;
      // null = no row yet. Keep asking only while the bounded wait is open.
      if (run === null) return graceExpired ? false : EVALUATION_POLL_MS;
      return isSettledRun(run) ? false : EVALUATION_POLL_MS;
    },
  });

  const run: EvaluationRun | null = runQuery.data ?? null;
  const settled = run !== null && isSettledRun(run);

  // Bounded wait for a row that may never appear.
  useEffect(() => {
    if (dispatchedAt === null || run !== null || failureFrame !== null) return;
    const remaining = dispatchedAt + EVALUATION_RECORD_GRACE_MS - Date.now();
    if (remaining <= 0) {
      setGraceExpired(true);
      return;
    }
    const timer = window.setTimeout(() => setGraceExpired(true), remaining);
    return () => window.clearTimeout(timer);
  }, [dispatchedAt, run, failureFrame]);

  // Live stages, where the provider has a channel. Closed as soon as the run
  // settles or a terminal frame arrives, so a finished run holds no socket.
  useEffect(() => {
    if (runId === null || settled || failureFrame !== null) return;
    if (!provider.subscribeEvaluationProgress) return;
    return provider.subscribeEvaluationProgress(runId, (event: EvaluationProgressEvent) => {
      // Narrow BEFORE touching stageIndex or metrics: the failure frame carries
      // stageIndex -1 (not a position) and metrics null.
      if (isEvaluationFailure(event)) {
        setFailureFrame(event.error);
        return;
      }
      setProgress((previous) => ({
        ...previous,
        stageIndex: event.stageIndex,
        metrics: event.metrics ?? previous.metrics,
        indeterminate: false,
      }));
    });
  }, [runId, settled, failureFrame]);

  useEffect(() => {
    if (!settled) return;
    void queryClient.invalidateQueries({ queryKey: ["evaluations"] });
  }, [settled, queryClient]);

  const phase: EvaluationRunPhase = mutation.isPending
    ? "dispatching"
    : mutation.isError
      ? "dispatch_failed"
      : runId === null
        ? "idle"
        : failureFrame !== null
          ? "start_failed"
          : run !== null
            ? settled
              ? "settled"
              : "running"
            : graceExpired
              ? "start_failed"
              : "waiting_for_record";

  /**
   * Why a dispatched run never produced a record. The terminal frame's own
   * text when we caught it; otherwise the bounded wait's explanation, because
   * the channel has no replay and the frame may simply have been missed.
   */
  const startFailure: string | null =
    failureFrame ??
    (phase === "start_failed"
      ? `No run record appeared within ${Math.round(EVALUATION_RECORD_GRACE_MS / 1000)}s and no failure frame was received. A run that aborts before its row exists 404s permanently, so this id will never resolve.`
      : null);

  const reset = useCallback(() => {
    setRunId(null);
    setDispatchedAt(null);
    setFailureFrame(null);
    setGraceExpired(false);
    setProgress(NO_PROGRESS);
    mutation.reset();
  }, [mutation]);

  return {
    /** The id the 202 returned, or null before one exists. */
    runId,
    phase,
    progress,
    /** The authoritative record, once a row exists. */
    run,
    /** Why the POST itself was refused. */
    dispatchError: mutation.error,
    /** Why a dispatched run never produced a record. */
    startFailure,
    /** True while the run cannot yet be read back in full. */
    isBusy: phase === "dispatching" || phase === "waiting_for_record" || phase === "running",
    start: (honeypotId: string) => mutation.mutate(honeypotId),
    reset,
  };
}
