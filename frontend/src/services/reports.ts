import { queryOptions } from "@tanstack/react-query";
import { provider } from "./index";

export const reportQueries = {
  list: () => queryOptions({ queryKey: ["reports"], queryFn: () => provider.getReports() }),
};
