import { queryOptions } from "@tanstack/react-query";
import { provider } from "./index";

export const sessionQueries = {
  list: (params?: { risk?: string; honeypotId?: string; q?: string }) =>
    queryOptions({
      queryKey: ["sessions", params ?? {}],
      queryFn: () => provider.getSessions(params),
    }),
  detail: (id: string) =>
    queryOptions({ queryKey: ["session", id], queryFn: () => provider.getSession(id) }),
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
  attacker: (ip: string) =>
    queryOptions({ queryKey: ["attacker", ip], queryFn: () => provider.getAttackerProfile(ip) }),
};
