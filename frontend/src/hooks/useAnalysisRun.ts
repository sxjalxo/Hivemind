import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { provider } from "@/services";
import { ANALYSIS_STAGES } from "@/services/analysis";
import type { AnalysisProgressEvent } from "@/services/provider";
import type { LiveAnalysisState, SessionAnalysis } from "@/types";

export interface AnalysisRunState {
  /** Live stage index, or null when the provider exposes no progress channel. */
  stageIndex: number | null;
  metrics: Omit<LiveAnalysisState, "sessionId"> | null;
  /** True when progress is genuinely unknown rather than merely at stage 0. */
  indeterminate: boolean;
}

const EMPTY: AnalysisRunState = { stageIndex: null, metrics: null, indeterminate: true };

/**
 * Drives POST /api/analyze/{session_id} and, where the provider offers one,
 * the accompanying progress channel.
 *
 * If no channel exists the run reports `indeterminate` so the UI can say
 * "running" without inventing a stage the backend never reported.
 */
export function useAnalysisRun(sessionId: string) {
  const queryClient = useQueryClient();
  const [run, setRun] = useState<AnalysisRunState>(EMPTY);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  const stopProgress = useCallback(() => {
    unsubscribeRef.current?.();
    unsubscribeRef.current = null;
  }, []);

  useEffect(() => stopProgress, [stopProgress]);

  const mutation = useMutation<SessionAnalysis, Error>({
    mutationFn: async () => {
      setRun({
        stageIndex: null,
        metrics: null,
        indeterminate: !provider.subscribeAnalysisProgress,
      });

      // Awaited, so the channel is listening before the analysis starts.
      // The backend publishes stage 0 immediately and the channel has no
      // replay, so firing the POST while the socket was still connecting
      // dropped however many early stages lost that race.
      if (provider.subscribeAnalysisProgress) {
        unsubscribeRef.current = await provider.subscribeAnalysisProgress(
          sessionId,
          (event: AnalysisProgressEvent) => {
            setRun((prev) => ({
              stageIndex: event.stageIndex,
              indeterminate: false,
              metrics: {
                progressPct: event.metrics?.progressPct ?? prev.metrics?.progressPct ?? 0,
                eventsProcessed:
                  event.metrics?.eventsProcessed ?? prev.metrics?.eventsProcessed ?? 0,
                commandsAnalyzed:
                  event.metrics?.commandsAnalyzed ?? prev.metrics?.commandsAnalyzed ?? 0,
                techniquesDetected:
                  event.metrics?.techniquesDetected ?? prev.metrics?.techniquesDetected ?? 0,
                iocsExtracted: event.metrics?.iocsExtracted ?? prev.metrics?.iocsExtracted ?? 0,
              },
            }));
          },
        );
      }

      try {
        return await provider.analyzeSession(sessionId);
      } finally {
        stopProgress();
      }
    },
    onSuccess: (analysis) => {
      setRun((prev) => ({ ...prev, stageIndex: ANALYSIS_STAGES.length, indeterminate: false }));
      queryClient.setQueryData(["analysis", analysis.id], analysis);
      void queryClient.invalidateQueries({ queryKey: ["analysis-history"] });
      void queryClient.invalidateQueries({ queryKey: ["session", sessionId] });
      void queryClient.invalidateQueries({ queryKey: ["mitre"] });
    },
    onError: stopProgress,
  });

  const reset = useCallback(() => {
    stopProgress();
    setRun(EMPTY);
    mutation.reset();
  }, [mutation, stopProgress]);

  return {
    analysis: mutation.data ?? null,
    isRunning: mutation.isPending,
    error: mutation.error,
    run,
    analyze: () => mutation.mutate(),
    reset,
  };
}
