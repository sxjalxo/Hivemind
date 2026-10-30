import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity } from "lucide-react";
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  LoadingState,
  Mono,
  Panel,
  ProvenanceBadge,
} from "@/components/common";
import { ChartTooltipCard } from "@/components/charts/ChartTooltip";
import { AXIS_STYLE, SERIES } from "@/components/charts/palette";
import { openedByLabel, periodName } from "@/components/sensor/periods";
import { sensorQueries } from "@/services/queries";
import { formatDateTime, formatNumber } from "@/utils/format";
import type { SensorTraffic } from "@/types";

const SERIES_META = [
  { key: "events", label: "Events", color: SERIES.events },
  { key: "sessions", label: "Sessions", color: SERIES.sessions },
] as const;

/** Rates are small; one decimal keeps 0.4/day from reading as 0. */
const rate = (value: number) => value.toLocaleString("en-US", { maximumFractionDigits: 1 });

/** Events and sessions per day, the periods between configuration changes, and who sent it. */
export function SensorTrafficPanel({ id, days }: { id: string; days: number }) {
  const { data, isPending, isError, error, refetch } = useQuery(sensorQueries.traffic(id, days));

  return (
    <Panel
      title="Traffic"
      description={`Last ${days} days on UTC days; the first and last are partial. Distinct counts are approximate above 3,000 per day and 10,000 per period.`}
      actions={<ProvenanceBadge kind="OBSERVED" showIcon={false} />}
    >
      {isPending ? (
        <LoadingState message="Loading traffic..." />
      ) : isError ? (
        <ErrorState title="Traffic unavailable" error={error} onRetry={() => void refetch()} />
      ) : data.perDay.every((point) => point.events === 0) ? (
        <EmptyState icon={Activity} title={`No traffic in the last ${days} days.`} />
      ) : (
        <TrafficBody data={data} />
      )}
    </Panel>
  );
}

function TrafficBody({ data }: { data: SensorTraffic }) {
  const protocolTotal = Object.values(data.protocols).reduce((sum, count) => sum + count, 0);

  // One line per boundary day. Only a boundary whose day is on the axis can be drawn.
  const axisDays = new Set(data.perDay.map((point) => point.day));
  const boundaries = new Map<string, string[]>();
  for (const { period } of data.periods) {
    if (period.openedBy.length === 0) continue;
    const day = period.start.slice(0, 10);
    if (!axisDays.has(day)) continue;
    boundaries.set(day, [...(boundaries.get(day) ?? []), openedByLabel(period)]);
  }

  return (
    <div className="space-y-6">
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
          <span className="text-xs text-muted-foreground">Dashed lines: a persona or change</span>
        </div>
        <div className="h-[260px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data.perDay} margin={{ top: 18, right: 8, bottom: 0, left: -14 }}>
              <CartesianGrid
                vertical={false}
                stroke={AXIS_STYLE.stroke}
                strokeOpacity={0.6}
                strokeDasharray="2 4"
              />
              <XAxis
                dataKey="day"
                tickLine={false}
                axisLine={false}
                tick={AXIS_STYLE.tick}
                minTickGap={24}
                tickFormatter={(day: string) => day.slice(5)}
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
              {[...boundaries].map(([day, labels]) => (
                <ReferenceLine
                  key={day}
                  x={day}
                  stroke="var(--color-muted-foreground)"
                  strokeDasharray="4 3"
                  label={{
                    value: labels.join(", "),
                    position: "insideTopRight",
                    fill: "var(--color-foreground)",
                    fontSize: 10,
                    fontFamily: "var(--font-mono)",
                  }}
                />
              ))}
              {SERIES_META.map((series) => (
                <Area
                  key={series.key}
                  type="monotone"
                  dataKey={series.key}
                  stroke={series.color}
                  strokeWidth={2}
                  fill="none"
                  isAnimationActive={false}
                  activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--color-card)" }}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div>
        <h3 className="mb-2 text-sm font-semibold text-foreground">By period</h3>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[640px] border-collapse text-sm">
            <thead>
              <tr className="border-b border-border">
                {["Persona", "From – to (UTC)", "Events/day", "Sessions/day", "Sources/day"].map(
                  (heading) => (
                    <th
                      key={heading}
                      className="label-caps whitespace-nowrap px-3 py-2 text-left font-normal"
                    >
                      {heading}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {data.periods.map((row) => (
                <tr key={row.period.start} className="border-b border-border/60 last:border-0">
                  <td className="px-3 py-2 text-xs text-foreground/90">
                    {periodName(row.period)}
                    {row.period.openedBy.length > 0 ? (
                      <span className="ml-1.5 font-mono text-[10px] text-muted-foreground">
                        {openedByLabel(row.period)}
                      </span>
                    ) : null}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2">
                    <Mono tone="muted" className="text-[11px]">
                      {formatDateTime(row.period.start)} – {formatDateTime(row.period.end)}
                    </Mono>
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
                    {rate(row.eventsPerDay)}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
                    {rate(row.sessionsPerDay)}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
                    {rate(row.sourcesPerDay)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <InlineNotice tone="info" className="mt-2">
          Periods differ in length, so compare events/day and sessions/day, not totals. Sources/day
          does not compare between periods of different length: repeat sources make a long
          period&apos;s distinct count grow more slowly than its length.
        </InlineNotice>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div>
          <h3 className="mb-2 text-sm font-semibold text-foreground">Top sources</h3>
          {data.topSources.length === 0 ? (
            <p className="text-xs text-muted-foreground">No sources in this window.</p>
          ) : (
            <table className="w-full border-collapse text-sm">
              <tbody>
                {data.topSources.map((source) => (
                  <tr key={source.ip} className="border-b border-border/60 last:border-0">
                    <td className="py-1.5 pr-3">
                      <Link
                        to="/attackers/$ip"
                        params={{ ip: source.ip }}
                        className="font-mono text-[13px] text-foreground underline-offset-4 hover:text-primary hover:underline"
                      >
                        {source.ip}
                      </Link>
                    </td>
                    <td className="py-1.5 pr-3 text-xs text-muted-foreground">
                      {source.country ?? "unresolved"}
                    </td>
                    <td className="py-1.5 text-right font-mono text-[13px] tabular-nums">
                      {formatNumber(source.events)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div>
          <h3 className="mb-2 text-sm font-semibold text-foreground">Protocols</h3>
          {protocolTotal === 0 ? (
            <p className="text-xs text-muted-foreground">No events in this window.</p>
          ) : (
            <ul className="space-y-2">
              {Object.entries(data.protocols).map(([protocol, count]) => (
                <li key={protocol}>
                  <div className="flex items-baseline justify-between gap-2 text-xs">
                    <span className="text-foreground/85">{protocol}</span>
                    <span className="font-mono tabular-nums text-muted-foreground">
                      {formatNumber(count)} · {((count / protocolTotal) * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="mt-1 h-1 rounded-full bg-muted">
                    <div
                      className="h-1 rounded-full"
                      style={{
                        width: `${(count / protocolTotal) * 100}%`,
                        backgroundColor: SERIES.events,
                      }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
