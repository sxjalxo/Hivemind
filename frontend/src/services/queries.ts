import { queryOptions } from "@tanstack/react-query";
import { provider } from "./index";
import type { LogQuery } from "@/types";

/**
 * Every `queryOptions` factory in the app except the evaluation ones, which
 * live in `./evaluation` alongside the socket subscription they are paired
 * with.
 */

export const honeypotsQuery = () =>
  queryOptions({ queryKey: ["honeypots"], queryFn: () => provider.getHoneypots() });

export const systemStatusQuery = () =>
  queryOptions({
    queryKey: ["system-status"],
    queryFn: () => provider.getSystemStatus(),
    refetchInterval: 30_000,
  });

export const sessionQueries = {
  list: (params?: { risk?: string; honeypotId?: string; q?: string }) =>
    queryOptions({
      queryKey: ["sessions", params ?? {}],
      queryFn: () => provider.getSessions(params),
    }),
  detail: (id: string) =>
    queryOptions({ queryKey: ["session", id], queryFn: () => provider.getSession(id) }),
  annotations: (id: string) =>
    queryOptions({
      queryKey: ["session-annotations", id],
      queryFn: () => provider.getAnnotations(id),
    }),
  replay: (id: string) =>
    queryOptions({
      queryKey: ["session-replay", id],
      queryFn: () => provider.getSessionReplay(id),
    }),
  identical: (id: string) =>
    queryOptions({
      queryKey: ["session-identical", id],
      queryFn: () => provider.getIdenticalSessions(id),
    }),
  campaigns: () =>
    queryOptions({ queryKey: ["campaigns"], queryFn: () => provider.getCampaigns() }),
  timeline: (id: string) =>
    queryOptions({
      queryKey: ["session-timeline", id],
      queryFn: () => provider.getSessionTimeline(id),
    }),
  events: (id: string) =>
    queryOptions({
      queryKey: ["session-events", id],
      queryFn: () => provider.getSessionEvents(id),
    }),
  reputation: (ip: string) =>
    queryOptions({
      queryKey: ["attacker-reputation", ip],
      queryFn: () => provider.getAttackerReputation(ip),
      staleTime: 60 * 60 * 1000, // the backend caches a day; no need to re-ask on every focus
    }),
  attacker: (ip: string) =>
    queryOptions({ queryKey: ["attacker", ip], queryFn: () => provider.getAttackerProfile(ip) }),
};

export const analysisQueries = {
  history: () =>
    queryOptions({ queryKey: ["analysis-history"], queryFn: () => provider.getAnalysisHistory() }),
  detail: (id: string) =>
    queryOptions({ queryKey: ["analysis", id], queryFn: () => provider.getAnalysis(id) }),
};

export const notablesQuery = () =>
  queryOptions({
    queryKey: ["notables"],
    queryFn: () => provider.getNotables(),
    refetchInterval: 60_000,
  });

export const dashboardQuery = (range: string) =>
  queryOptions({ queryKey: ["dashboard", range], queryFn: () => provider.getDashboard(range) });

export const logFacetsQuery = () =>
  queryOptions({ queryKey: ["log-facets"], queryFn: () => provider.getLogFacets() });

export const logSearchQuery = (query: LogQuery) =>
  queryOptions({ queryKey: ["logs", query], queryFn: () => provider.queryLogs(query) });

export const mitreCoverageQuery = (sessionId?: string) =>
  queryOptions({
    queryKey: ["mitre", sessionId ?? "all"],
    queryFn: () => provider.getMitreCoverage(sessionId ? { sessionId } : undefined),
  });

export const indicatorsQuery = (params?: { type?: string; q?: string }) =>
  queryOptions({
    queryKey: ["indicators", params ?? {}],
    queryFn: () => provider.getIndicators(params),
  });

export const indicatorCountsQuery = () =>
  queryOptions({
    queryKey: ["indicators", "counts"],
    queryFn: () => provider.getIndicatorCounts(),
  });

export const reportsQuery = () =>
  queryOptions({ queryKey: ["reports"], queryFn: () => provider.getReports() });
