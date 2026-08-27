import { Link } from "@tanstack/react-router";
import { ArrowUpRight } from "lucide-react";
import { CopyButton, Mono, RiskBadge, asRiskLevel } from "@/components/common";
import { formatNumber } from "@/utils/format";

export interface TopAttackerRow {
  ip: string;
  country: string;
  events: number;
  sessions: number;
  risk: string;
  lastSeen: string;
}

/**
 * Highest-volume source addresses. Collapses to a card list below `md` so the
 * columns never wrap into an unreadable grid on mobile.
 */
export function TopAttackersTable({ rows }: { rows: TopAttackerRow[] }) {
  return (
    <>
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full min-w-[560px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="label-caps px-3 py-2 text-left font-normal">IP</th>
              <th className="label-caps px-3 py-2 text-left font-normal">Country</th>
              <th className="label-caps px-3 py-2 text-right font-normal">Events</th>
              <th className="label-caps px-3 py-2 text-right font-normal">Sessions</th>
              <th className="label-caps px-3 py-2 text-left font-normal">Risk</th>
              <th className="label-caps px-3 py-2 text-right font-normal">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.ip}
                className="group border-b border-border/60 transition-colors last:border-0 hover:bg-accent/30"
              >
                <td className="px-3 py-2">
                  <span className="flex items-center gap-1">
                    <Link
                      to="/attackers/$ip"
                      params={{ ip: row.ip }}
                      className="font-mono text-[13px] text-foreground underline-offset-4 hover:text-primary hover:underline"
                    >
                      {row.ip}
                    </Link>
                    <CopyButton
                      value={row.ip}
                      className="opacity-0 group-hover:opacity-100 focus:opacity-100"
                    />
                  </span>
                </td>
                <td className="px-3 py-2">
                  <Mono tone="muted" className="text-xs">
                    {row.country}
                  </Mono>
                </td>
                <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
                  {formatNumber(row.events)}
                </td>
                <td className="px-3 py-2 text-right font-mono text-[13px] tabular-nums">
                  {row.sessions}
                </td>
                <td className="px-3 py-2">
                  <RiskBadge level={asRiskLevel(row.risk)} />
                </td>
                <td className="px-3 py-2 text-right">
                  <Mono tone="muted" className="text-xs">
                    {row.lastSeen}
                  </Mono>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="space-y-2 md:hidden">
        {rows.map((row) => (
          <li key={row.ip} className="rounded-md border border-border bg-surface/50 p-3">
            <div className="flex items-center justify-between gap-2">
              <Link
                to="/attackers/$ip"
                params={{ ip: row.ip }}
                className="flex items-center gap-1 font-mono text-[13px] text-foreground hover:text-primary"
              >
                {row.ip}
                <ArrowUpRight className="size-3 text-muted-foreground" aria-hidden />
              </Link>
              <RiskBadge level={asRiskLevel(row.risk)} />
            </div>
            <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Country</dt>
                <dd className="font-mono">{row.country}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Events</dt>
                <dd className="font-mono tabular-nums">{formatNumber(row.events)}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Sessions</dt>
                <dd className="font-mono tabular-nums">{row.sessions}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Last seen</dt>
                <dd className="font-mono">{row.lastSeen}</dd>
              </div>
            </dl>
          </li>
        ))}
      </ul>
    </>
  );
}
