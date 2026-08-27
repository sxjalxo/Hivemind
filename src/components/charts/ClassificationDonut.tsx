import { useMemo } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { ChartTooltipCard, LegendRow } from "./ChartTooltip";
import { OTHER_COLOR, hasOwnHue, tacticColor } from "./palette";
import { formatNumber } from "@/utils/format";

export interface ClassificationSlice {
  name: string;
  value: number;
}

interface Arc {
  name: string;
  value: number;
  color: string;
  /** Tactics folded into the neutral "Other" arc, listed so nothing is hidden. */
  members?: string[];
}

/**
 * Attack classification breakdown.
 *
 * Only seven hues survive colour-blindness validation, so tactics without a
 * dedicated hue collapse into one neutral "Other" arc — but every tactic keeps
 * its own labelled row with a count in the legend, so no data is hidden.
 */
export function ClassificationDonut({ data }: { data: ClassificationSlice[] }) {
  const total = data.reduce((sum, slice) => sum + slice.value, 0);

  const arcs = useMemo<Arc[]>(() => {
    const named = data.filter((slice) => hasOwnHue(slice.name));
    const rest = data.filter((slice) => !hasOwnHue(slice.name));
    const arcList: Arc[] = named.map((slice) => ({
      name: slice.name,
      value: slice.value,
      color: tacticColor(slice.name),
    }));
    if (rest.length > 0) {
      arcList.push({
        name: "Other tactics",
        value: rest.reduce((sum, slice) => sum + slice.value, 0),
        color: OTHER_COLOR,
        members: rest.map((slice) => slice.name),
      });
    }
    return arcList;
  }, [data]);

  const share = (value: number) => (total === 0 ? 0 : (value / total) * 100);
  const legend = [...data].sort((a, b) => b.value - a.value);

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
      <div className="relative h-[188px] w-full shrink-0 lg:w-[172px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={arcs}
              dataKey="value"
              nameKey="name"
              innerRadius="62%"
              outerRadius="94%"
              paddingAngle={2}
              stroke="var(--color-card)"
              strokeWidth={2}
              startAngle={90}
              endAngle={-270}
              isAnimationActive={false}
            >
              {arcs.map((arc) => (
                <Cell key={arc.name} fill={arc.color} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const arc = payload[0]?.payload as Arc | undefined;
                if (!arc) return null;
                return (
                  <ChartTooltipCard
                    title={arc.name}
                    rows={[{ label: "Sessions", value: arc.value, color: arc.color }]}
                    footer={
                      arc.members
                        ? `${share(arc.value).toFixed(1)}% — ${arc.members.join(", ")}`
                        : `${share(arc.value).toFixed(1)}% of classified activity`
                    }
                  />
                );
              }}
            />
          </PieChart>
        </ResponsiveContainer>

        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-xl font-semibold tabular-nums text-foreground">
            {formatNumber(total)}
          </span>
          <span className="label-caps">Classified</span>
        </div>
      </div>

      <div className="min-w-0 flex-1">
        <div className="max-h-[188px] space-y-px overflow-y-auto pr-1">
          {legend.map((slice) => (
            <LegendRow
              key={slice.name}
              color={tacticColor(slice.name)}
              label={slice.name}
              value={slice.value}
              share={share(slice.value)}
              muted={!hasOwnHue(slice.name)}
            />
          ))}
        </div>
        <p className="mt-2 border-t border-border pt-2 text-[11px] leading-relaxed text-muted-foreground">
          Tactics shown in grey share the neutral arc; their counts are exact.
        </p>
      </div>
    </div>
  );
}
