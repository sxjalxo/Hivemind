import type { SensorPeriod } from "@/types";

/** What a period is called: the persona in force, said plainly when none was ever recorded. */
export const periodName = (period: SensorPeriod) => period.persona ?? "no persona recorded";

/** What opened a period, for labels: `persona:web-server` reads as `web-server`. */
export const openedByLabel = (period: SensorPeriod) =>
  period.openedBy.map((item) => item.replace(/^persona:/, "")).join(", ");
