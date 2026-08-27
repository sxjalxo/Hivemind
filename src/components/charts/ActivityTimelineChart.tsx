import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartTooltipCard } from "./ChartTooltip";
import { AXIS_STYLE, SERIES } from "./palette";
import { formatNumber } from "@/utils/format";

export interface TimelinePoint {
  t: string;
  events: number;
  highRisk: number;
}

const SERIES_META = [
  { key: "events", label: "Events", color: SERIES.events },
  { key: "highRisk", label: "High-risk events", color: SERIES.highRisk },
] as const;

/**
 * Attacker activity over the selected window. Two series on one shared axis —
 * never a second y-scale.
 */
export function ActivityTimelineChart({ data }: { data: TimelinePoint[] }) {
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1.5">
        {SERIES_META.map((series) => (
          <span key={series.key} className="flex items-center gap-1.5">
            <span
              className="size-2 rounded-[2px]"
              style={{ backgroundColor: series.color }}
              aria-hidden
            />
            <span className="text-xs text-muted-foreground">{series.label}</span>
          </span>
        ))}
      </div>

      <div className="h-[248px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -14 }}>
            <defs>
              <linearGradient id="fillEvents" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={SERIES.events} stopOpacity={0.35} />
                <stop offset="100%" stopColor={SERIES.events} stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="fillHighRisk" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={SERIES.highRisk} stopOpacity={0.35} />
                <stop offset="100%" stopColor={SERIES.highRisk} stopOpacity={0.02} />
              </linearGradient>
            </defs>

            <CartesianGrid
              vertical={false}
              stroke={AXIS_STYLE.stroke}
              strokeOpacity={0.6}
              strokeDasharray="2 4"
            />
            <XAxis
              dataKey="t"
              tickLine={false}
              axisLine={false}
              tick={AXIS_STYLE.tick}
              minTickGap={24}
            />
            <YAxis
              tickLine={false}
              axisLine={false}
              tick={AXIS_STYLE.tick}
              width={54}
              tickFormatter={(value: number) => formatNumber(value)}
            />
            <Tooltip
              cursor={{ stroke: "var(--color-border-strong)", strokeWidth: 1 }}
              content={({ active, payload, label }) => {
                if (!active || !payload?.length) return null;
                return (
                  <ChartTooltipCard
                    title={String(label)}
                    rows={SERIES_META.map((series) => ({
                      label: series.label,
                      value: Number(
                        payload.find((item) => item.dataKey === series.key)?.value ?? 0,
                      ),
                      color: series.color,
                    }))}
                  />
                );
              }}
            />

            <Area
              type="monotone"
              dataKey="events"
              stroke={SERIES.events}
              strokeWidth={2}
              fill="url(#fillEvents)"
              isAnimationActive={false}
              activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--color-card)" }}
            />
            <Area
              type="monotone"
              dataKey="highRisk"
              stroke={SERIES.highRisk}
              strokeWidth={2}
              fill="url(#fillHighRisk)"
              isAnimationActive={false}
              activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--color-card)" }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
