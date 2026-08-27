import { queryOptions } from "@tanstack/react-query";
import { provider } from "./index";
import type { LogQuery } from "@/types";

export const logQueries = {
  search: (query: LogQuery) =>
    queryOptions({ queryKey: ["logs", query], queryFn: () => provider.queryLogs(query) }),
};
