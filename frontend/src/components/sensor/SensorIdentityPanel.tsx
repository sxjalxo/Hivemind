import { useQuery } from "@tanstack/react-query";
import { Server } from "lucide-react";
import { EmptyState, ErrorState, LoadingState, Mono, Panel } from "@/components/common";
import { DescribedValue } from "@/components/sensor/DescribedValue";
import { sensorQueries } from "@/services/queries";
import { formatDateTime, formatNumber } from "@/utils/format";
import type { SensorProfile } from "@/types";

/** What the sensor is, and the dated history of what it has been disguised as. */
export function SensorIdentityPanel({ id }: { id: string }) {
  const { data, isPending, isError, error, refetch } = useQuery(sensorQueries.profile(id));

  // Loading and error occupy the loaded layout's grid, so nothing jumps when data arrives.
  if (isPending || isError) {
    return (
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          title="Identity"
          description="Observed fields, and values derived with their source."
        >
          {isPending ? (
            <LoadingState message="Loading sensor..." />
          ) : (
            <ErrorState
              title="Sensor profile unavailable"
              error={error}
              onRetry={() => void refetch()}
            />
          )}
        </Panel>
        <Panel
          className="xl:col-span-2"
          title="Persona and configuration history"
          description="Oldest first. Every row is something recorded, not inferred."
        >
          {isPending ? <LoadingState message="Loading history..." /> : null}
        </Panel>
      </div>
    );
  }

  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Panel title="Identity" description="Observed fields, and values derived with their source.">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
          <Fact label="Name">{data.name}</Fact>
          <Fact label="Address">
            <Mono className="text-[13px]">{data.address}</Mono>
          </Fact>
          <Fact label="Type">
            <DescribedValue item={data.type} />
          </Fact>
          <Fact label="Operating system">
            <DescribedValue item={data.os} />
          </Fact>
          <Fact label="First seen">
            <Mono className="text-[13px]">{formatDateTime(data.firstSeen)}</Mono>
          </Fact>
          <Fact label="Last seen">
            <Mono className="text-[13px]">{formatDateTime(data.lastSeen)}</Mono>
          </Fact>
        </dl>
        <div className="mt-4 border-t border-border pt-3">
          <p className="label-caps">Protocols (events, all time)</p>
          {Object.keys(data.protocols).length === 0 ? (
            <p className="mt-1 text-xs text-muted-foreground">none observed</p>
          ) : (
            <ul className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1">
              {Object.entries(data.protocols).map(([protocol, count]) => (
                <li key={protocol} className="text-xs text-foreground/90">
                  {protocol} <Mono tone="muted">{formatNumber(count)}</Mono>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Panel>

      <Panel
        className="xl:col-span-2"
        title="Persona and configuration history"
        description="Oldest first. Every row is something recorded, not inferred."
        bodyClassName="p-0"
      >
        <History profile={data} />
      </Panel>
    </div>
  );
}

function History({ profile }: { profile: SensorProfile }) {
  const rows = [
    ...profile.deployments.map((d) => ({
      at: d.deployedAt,
      what: `Persona ${d.persona} deployed`,
      detail: d.digest,
      by: d.deployedBy,
    })),
    ...profile.changes.map((c) => ({
      at: c.at,
      what: c.kind,
      detail: c.detail,
      by: c.recordedBy,
    })),
  ].sort((a, b) => Date.parse(a.at) - Date.parse(b.at));

  if (rows.length === 0) {
    return (
      <EmptyState
        icon={Server}
        title="No persona or configuration change recorded."
        description="Persona deployments and recorded changes appear here, dated."
      />
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[560px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border">
            {["When (UTC)", "What", "Detail", "By"].map((heading) => (
              <th
                key={heading}
                className="label-caps whitespace-nowrap px-3 py-2 text-left font-normal"
              >
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} className="border-b border-border/60 align-top last:border-0">
              <td className="whitespace-nowrap px-3 py-2">
                <Mono tone="muted" className="text-[11px]">
                  {formatDateTime(row.at)}
                </Mono>
              </td>
              <td className="px-3 py-2 text-xs text-foreground/90">{row.what}</td>
              <td className="max-w-[320px] break-words px-3 py-2 font-mono text-[11px] text-muted-foreground">
                {row.detail}
              </td>
              <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{row.by}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="label-caps">{label}</dt>
      <dd className="mt-1 min-w-0 truncate text-sm text-foreground/90">{children}</dd>
    </div>
  );
}
