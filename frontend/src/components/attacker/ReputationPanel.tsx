import { useQuery } from "@tanstack/react-query";
import { InlineNotice, Mono, Panel, ProvenanceBadge } from "@/components/common";
import { sessionQueries } from "@/services/queries";
import { formatDateTime, formatNumber } from "@/utils/format";

/**
 * What OTHER people have reported about this address, from AbuseIPDB.
 *
 * Labelled THIRD PARTY and kept in its own panel: none of it was observed by
 * this honeypot, and none of it feeds the risk score, techniques or
 * indicators on this page. A score of 100 here is AbuseIPDB's confidence,
 * computed from strangers' reports -- not a finding.
 */
export function ReputationPanel({ ip }: { ip: string }) {
  const { data, isPending, isError } = useQuery(sessionQueries.reputation(ip));

  return (
    <Panel
      title="Third-party reputation"
      description="What other AbuseIPDB users have reported about this address. Not observed here."
      actions={<ProvenanceBadge kind="THIRD PARTY" />}
    >
      {isPending ? (
        <p className="text-xs text-muted-foreground">Asking AbuseIPDB...</p>
      ) : isError ? (
        <InlineNotice tone="critical">The reputation lookup could not be read.</InlineNotice>
      ) : data.status === "ok" ? (
        <div className="space-y-3">
          <div>
            <div className="flex items-baseline justify-between">
              <span className="label-caps">AbuseIPDB confidence of abuse</span>
              <Mono className="text-lg font-semibold">{data.abuseConfidence ?? "—"}%</Mono>
            </div>
            <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full bg-muted-foreground"
                style={{ width: `${Math.max(0, Math.min(100, data.abuseConfidence ?? 0))}%` }}
              />
            </div>
          </div>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm md:grid-cols-4">
            {[
              ["Reports", data.totalReports != null ? formatNumber(data.totalReports) : "—"],
              [
                "Distinct reporters",
                data.distinctReporters != null ? formatNumber(data.distinctReporters) : "—",
              ],
              [
                "Last reported",
                data.lastReportedAt ? formatDateTime(data.lastReportedAt) : "never",
              ],
              ["Tor exit", data.isTor == null ? "—" : data.isTor ? "yes" : "no"],
              ["ISP", data.isp ?? "—"],
              ["Usage", data.usageType ?? "—"],
              ["Domain", data.domain ?? "—"],
              ["Their country", data.countryCode ?? "—"],
            ].map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt className="label-caps">{label}</dt>
                <dd className="truncate text-foreground/90">{value}</dd>
              </div>
            ))}
          </dl>
          <p className="text-[11px] text-muted-foreground">
            Checked {data.checkedAt ? formatDateTime(data.checkedAt) : "just now"}; answers are
            cached for a day. Only the IP address was sent.
          </p>
        </div>
      ) : (
        <InlineNotice
          tone={data.status === "not_configured" || data.status === "not_public" ? "info" : "warn"}
        >
          {data.detail ?? "No reputation is available for this address."}
        </InlineNotice>
      )}
    </Panel>
  );
}
