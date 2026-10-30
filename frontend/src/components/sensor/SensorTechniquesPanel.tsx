import { useQuery } from "@tanstack/react-query";
import { Target } from "lucide-react";
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  LoadingState,
  MitreBadge,
  Mono,
  Panel,
  ProvenanceBadge,
} from "@/components/common";
import { periodName } from "@/components/sensor/periods";
import { sensorQueries } from "@/services/queries";
import { formatDateTime, formatNumber } from "@/utils/format";

/** Techniques the rulebook finds in the commands the sensor received, split by period. */
export function SensorTechniquesPanel({ id, days }: { id: string; days: number }) {
  const { data, isPending, isError, error, refetch } = useQuery(sensorQueries.techniques(id, days));

  return (
    <Panel
      title="Techniques"
      description={`Rule-matched over the distinct commands received in the last ${days} days. No model is involved.`}
      actions={<ProvenanceBadge kind="OBSERVED" showIcon={false} />}
      bodyClassName="p-0"
    >
      {isPending ? (
        <LoadingState message="Matching commands against the rulebook..." />
      ) : isError ? (
        <ErrorState title="Techniques unavailable" error={error} onRetry={() => void refetch()} />
      ) : (
        <>
          {data.truncated ? (
            <InlineNotice tone="warn" className="m-4 mb-0">
              More distinct commands were received than the {formatNumber(data.commandsConsidered)}{" "}
              considered here, so this list is incomplete.
            </InlineNotice>
          ) : null}
          {data.techniques.length === 0 ? (
            <EmptyState
              icon={Target}
              title="No technique matched."
              description={`${formatNumber(data.commandsConsidered)} distinct commands were checked against the rulebook in the last ${days} days.`}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] border-collapse text-sm">
                <thead>
                  <tr className="border-b border-border">
                    {["Technique", "Tactic", "Events", "Sessions", "First seen", "Last seen"].map(
                      (heading) => (
                        <th
                          key={heading}
                          className="label-caps whitespace-nowrap px-3 py-2 text-left font-normal"
                        >
                          {heading}
                        </th>
                      ),
                    )}
                    {data.periods.map((period) => (
                      <th
                        key={period.start}
                        title={`${formatDateTime(period.start)} – ${formatDateTime(period.end)}`}
                        className="label-caps whitespace-nowrap px-3 py-2 text-right font-normal"
                      >
                        {periodName(period)}
                        <span className="block font-mono text-[10px] normal-case">
                          {period.start.slice(0, 10)}
                        </span>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.techniques.map((technique) => (
                    <tr
                      key={`${technique.ruleId}-${technique.techniqueId}`}
                      className="border-b border-border/60 last:border-0 hover:bg-accent/30"
                    >
                      <td className="px-3 py-2">
                        <MitreBadge techniqueId={technique.techniqueId} name={technique.name} />
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-xs text-foreground/85">
                        {technique.tactic}
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
                        {formatNumber(technique.events)}
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
                        {formatNumber(technique.sessions)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">
                        <Mono tone="muted" className="text-[11px]">
                          {formatDateTime(technique.firstSeen)}
                        </Mono>
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">
                        <Mono tone="muted" className="text-[11px]">
                          {formatDateTime(technique.lastSeen)}
                        </Mono>
                      </td>
                      {technique.perPeriod.map((count, index) => (
                        <td
                          key={data.periods[index]?.start ?? index}
                          className="px-3 py-2 text-right font-mono text-[13px] tabular-nums"
                        >
                          {formatNumber(count)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}
