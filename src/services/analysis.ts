import { queryOptions } from "@tanstack/react-query";
import { provider } from "./index";
import type { AnalysisProgress, AnalysisStage } from "@/types";

export const analysisQueries = {
  history: () =>
    queryOptions({ queryKey: ["analysis-history"], queryFn: () => provider.getAnalysisHistory() }),
  detail: (id: string) =>
    queryOptions({ queryKey: ["analysis", id], queryFn: () => provider.getAnalysis(id) }),
};

export const ANALYSIS_STAGES: { stage: AnalysisStage; label: string }[] = [
  { stage: "parsing_logs", label: "Parsing logs" },
  { stage: "identifying_patterns", label: "Identifying behavioral patterns" },
  { stage: "classifying_behavior", label: "Classifying attacker behavior" },
  { stage: "extracting_indicators", label: "Extracting indicators" },
  { stage: "mapping_mitre", label: "Mapping MITRE ATT&CK techniques" },
  { stage: "generating_intel", label: "Generating threat intelligence" },
  { stage: "generating_recommendations", label: "Generating recommendations" },
];

export function stageList(activeIndex: number): AnalysisProgress[] {
  return ANALYSIS_STAGES.map((item, index) => ({
    ...item,
    state: index < activeIndex ? "done" : index === activeIndex ? "active" : "pending",
  }));
}

export const dashboardQuery = (range: string) =>
  queryOptions({ queryKey: ["dashboard", range], queryFn: () => provider.getDashboard(range) });
