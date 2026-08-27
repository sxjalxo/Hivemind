import { queryOptions } from "@tanstack/react-query";
import { provider } from "./index";

export const honeypotQueries = {
  list: () => queryOptions({ queryKey: ["honeypots"], queryFn: () => provider.getHoneypots() }),
};

export const systemStatusQuery = () =>
  queryOptions({
    queryKey: ["system-status"],
    queryFn: () => provider.getSystemStatus(),
    refetchInterval: 30_000,
  });
