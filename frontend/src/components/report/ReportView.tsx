import { Link } from "@tanstack/react-router";
import { EvidenceList } from "@/components/session/EvidenceList";
import { SessionTimeline } from "@/components/session/SessionTimeline";
import {
  ConfidenceBar,
  Mono,
  ProvenanceBadge,
  RiskBadge,
  RiskScoreMeter,
} from "@/components/common";
import { formatDateTime, formatPct } from "@/utils/format";
import { cn } from "@/lib/utils";
import type { ThreatReport } from "@/types";

/**
 * Analyst-facing threat report. Sections mirror the export format so the PDF,
 * the JSON and this screen never drift apart.
 */
export function ReportView({ report }: { report: ThreatReport }) {
  return (
    <article className="space-y-6">
      <ReportSection title="Executive Summary" provenance="AI INFERENCE">
        <p className="text-sm leading-relaxed text-foreground/90">{report.executiveSummary}</p>
      </ReportSection>

      <ReportSection title="Incident Overview" provenance="OBSERVED">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 md:grid-cols-3">
          <Fact label="Attacker">
            <Link
              to="/attackers/$ip"
              params={{ ip: report.incidentOverview.attackerIp }}
              className="font-mono text-[13px] text-foreground hover:text-primary hover:underline"
            >
              {report.incidentOverview.attackerIp}
            </Link>
          </Fact>
          <Fact label="Target">
            <span className="text-sm text-foreground/90">{report.incidentOverview.target}</span>
          </Fact>
          <Fact label="Protocol">
            <Mono className="text-[13px]">{report.incidentOverview.protocol}</Mono>
          </Fact>
          <Fact label="Time range">
            <Mono className="text-[13px]">{report.incidentOverview.timeRange}</Mono>
          </Fact>
          <Fact label="Session">
            <Link
              to="/sessions/$sessionId"
              params={{ sessionId: report.sessionId }}
              className="font-mono text-[13px] text-foreground hover:text-primary hover:underline"
            >
              {report.sessionId}
            </Link>
          </Fact>
          <Fact label="Risk">
            <RiskBadge
              level={report.incidentOverview.risk}
              score={report.incidentOverview.riskScore}
              size="md"
            />
          </Fact>
        </dl>
      </ReportSection>

      <ReportSection title="Attack Timeline" provenance="OBSERVED">
        <SessionTimeline events={report.timeline} />
      </ReportSection>

      <ReportSection title="Attacker Behaviour" provenance="AI INFERENCE">
        <p className="text-sm font-semibold text-foreground">
          {report.attackerBehavior.classification}
        </p>
        <p className="mt-1.5 text-sm leading-relaxed text-foreground/85">
          {report.attackerBehavior.explanation}
        </p>
        <div className="mt-3 max-w-xs">
          <ConfidenceBar value={report.attackerBehavior.confidence} />
        </div>
      </ReportSection>

      <ReportSection title="MITRE ATT&CK Mapping" provenance="AI INFERENCE">
        {report.mitre.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No ATT&amp;CK techniques have been associated with this session.
          </p>
        ) : (
          <ul className="space-y-3">
            {report.mitre.map((technique) => (
              <li
                key={technique.techniqueId}
                className="rounded-md border border-border bg-background/40 p-3"
              >
                <div className="flex flex-wrap items-baseline gap-2">
                  <Mono className="rounded border border-primary/40 bg-primary/12 px-1.5 py-[2px] text-[11px] font-semibold text-primary">
                    {technique.techniqueId}
                  </Mono>
                  <span className="text-sm font-medium text-foreground">
                    {technique.techniqueName}
                  </span>
                  <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                    {technique.tactic}
                  </span>
                  <span className="ml-auto font-mono text-xs tabular-nums text-muted-foreground">
                    {formatPct(technique.confidence)} confidence
                  </span>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-foreground/80">
                  {technique.aiExplanation}
                </p>
                <div className="mt-2.5">
                  <p className="label-caps mb-1.5">Evidence</p>
                  <EvidenceList evidence={technique.evidence} dense />
                </div>
              </li>
            ))}
          </ul>
        )}
      </ReportSection>

      <ReportSection title="Indicators of Compromise" provenance="OBSERVED">
        {report.indicators.length === 0 ? (
          <p className="text-xs text-muted-foreground">No indicators were extracted.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] border-collapse text-sm">
              <thead>
                <tr className="border-b border-border">
                  {["Type", "Indicator", "Confidence", "Source", "Last seen"].map((heading) => (
                    <th
                      key={heading}
                      className="label-caps whitespace-nowrap px-2 py-1.5 text-left font-normal"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.indicators.map((indicator) => (
                  <tr key={indicator.id} className="border-b border-border/60 last:border-0">
                    <td className="px-2 py-1.5 font-mono text-[10px] uppercase text-muted-foreground">
                      {indicator.type}
                    </td>
                    <td className="max-w-[280px] px-2 py-1.5">
                      <Mono className="block truncate text-[13px]">{indicator.value}</Mono>
                    </td>
                    <td className="px-2 py-1.5">
                      <Mono tone="muted" className="text-xs">
                        {formatPct(indicator.confidence)}
                      </Mono>
                    </td>
                    <td className="px-2 py-1.5">
                      <ProvenanceBadge kind={indicator.source} showIcon={false} />
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5">
                      <Mono tone="muted" className="text-xs">
                        {formatDateTime(indicator.lastSeen)}
                      </Mono>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ReportSection>

      <ReportSection title="Threat Assessment" provenance="AI INFERENCE">
        <div className="flex flex-wrap items-start gap-6">
          <div>
            <p className="label-caps mb-1.5">Assessed level</p>
            <RiskBadge level={report.threatAssessment.level} size="md" />
          </div>
          <div className="min-w-[180px]">
            <ConfidenceBar value={report.threatAssessment.confidence} />
          </div>
        </div>
        <p className="mt-3 text-sm leading-relaxed text-foreground/85">
          {report.threatAssessment.narrative}
        </p>
      </ReportSection>

      <ReportSection title="Recommended Actions" provenance="AI INFERENCE">
        <ol className="space-y-2">
          {report.recommendedActions.map((action) => (
            <li
              key={action.action}
              className="flex items-start gap-2.5 rounded-md border border-border bg-background/40 px-3 py-2"
            >
              <span
                className={cn(
                  "mt-px shrink-0 rounded border px-1.5 py-[2px] font-mono text-[10px] font-semibold",
                  action.priority === "P1" && "border-critical/40 bg-critical/12 text-critical",
                  action.priority === "P2" && "border-high/40 bg-high/12 text-high",
                  action.priority === "P3" && "border-info/40 bg-info/12 text-info",
                )}
              >
                {action.priority}
              </span>
              <span className="min-w-0">
                <span className="block text-sm text-foreground">{action.action}</span>
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  {action.rationale}
                </span>
              </span>
            </li>
          ))}
        </ol>
      </ReportSection>
    </article>
  );
}

function ReportSection({
  title,
  provenance,
  children,
}: {
  title: string;
  provenance: "OBSERVED" | "AI INFERENCE" | "CORRELATED" | "STATIC ANALYSIS";
  children: React.ReactNode;
}) {
  return (
    <section>
      <header className="mb-3 flex flex-wrap items-center gap-2 border-b border-border pb-2">
        <h2 className="text-sm font-semibold tracking-tight text-foreground">{title}</h2>
        <ProvenanceBadge kind={provenance} showIcon={false} />
      </header>
      {children}
    </section>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="label-caps">{label}</dt>
      <dd className="mt-1 min-w-0">{children}</dd>
    </div>
  );
}
