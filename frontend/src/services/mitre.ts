import { queryOptions } from "@tanstack/react-query";
import { provider } from "./index";

export const mitreQueries = {
  coverage: (sessionId?: string) =>
    queryOptions({
      queryKey: ["mitre", sessionId ?? "all"],
      queryFn: () => provider.getMitreCoverage(sessionId ? { sessionId } : undefined),
    }),
};
