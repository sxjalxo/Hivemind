import { queryOptions } from "@tanstack/react-query";
import { provider } from "./index";

export const threatIntelQueries = {
  indicators: (params?: { type?: string; q?: string }) =>
    queryOptions({
      queryKey: ["indicators", params ?? {}],
      queryFn: () => provider.getIndicators(params),
    }),
};
