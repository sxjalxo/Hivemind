import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

export const TIME_RANGES = [
  { id: "15m", label: "Last 15 minutes", short: "15m" },
  { id: "1h", label: "Last hour", short: "1h" },
  { id: "24h", label: "Last 24 hours", short: "24h" },
  { id: "7d", label: "Last 7 days", short: "7d" },
] as const;

export type TimeRangeId = (typeof TIME_RANGES)[number]["id"];

interface TimeRangeContextValue {
  range: TimeRangeId;
  setRange: (range: TimeRangeId) => void;
  label: string;
}

const TimeRangeContext = createContext<TimeRangeContextValue | null>(null);

/** Shared query window driving the top bar selector and every time-scoped panel. */
export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [range, setRange] = useState<TimeRangeId>("24h");

  const value = useMemo<TimeRangeContextValue>(
    () => ({
      range,
      setRange,
      label: TIME_RANGES.find((item) => item.id === range)?.label ?? "Last 24 hours",
    }),
    [range],
  );

  return <TimeRangeContext.Provider value={value}>{children}</TimeRangeContext.Provider>;
}

export function useTimeRange(): TimeRangeContextValue {
  const context = useContext(TimeRangeContext);
  if (!context) throw new Error("useTimeRange must be used inside <TimeRangeProvider>");
  return context;
}
