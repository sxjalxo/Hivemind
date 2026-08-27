import type { ThreatReport } from "@/types";
import { formatDateTime, formatPct } from "./format";

/**
 * Renders a report as Markdown for the "Copy Report" action.
 *
 * Provenance labels are carried into the text, so a report pasted into a ticket
 * still distinguishes recorded evidence from AI interpretation.
 */
export function reportToMarkdown(report: ThreatReport): string {
  const lines: string[] = [];
  const push = (...entries: string[]) => lines.push(...entries);

  push(`# ${report.title}`, "");
  push(
    `- Report ID: ${report.id}`,
    `- Session: ${report.sessionId}`,
    `- Generated: ${formatDateTime(report.createdAt)} by ${report.generatedBy}`,
    "",
  );

  push("## Executive Summary  [AI INFERENCE]", "", report.executiveSummary, "");

  const overview = report.incidentOverview;
  push(
    "## Incident Overview  [OBSERVED]",
    "",
    `- Attacker: ${overview.attackerIp}`,
    `- Target: ${overview.target}`,
    `- Time range: ${overview.timeRange}`,
    `- Protocol: ${overview.protocol}`,
    `- Risk: ${overview.risk.toUpperCase()} (${overview.riskScore}/100)`,
    "",
  );

  push("## Attack Timeline  [OBSERVED]", "");
  for (const event of report.timeline) {
    const technique = event.techniqueId ? ` (${event.techniqueId})` : "";
    push(`- ${formatDateTime(event.timestamp)} — ${event.label}${technique}`);
    if (event.detail) push(`    ${event.detail}`);
  }
  push("");

  push(
    "## Attacker Behaviour  [AI INFERENCE]",
    "",
    `**${report.attackerBehavior.classification}** (confidence ${formatPct(report.attackerBehavior.confidence)})`,
    "",
    report.attackerBehavior.explanation,
    "",
  );

  push("## MITRE ATT&CK Mapping  [AI INFERENCE, evidence OBSERVED]", "");
  if (report.mitre.length === 0) {
    push("No ATT&CK techniques have been associated with this session.", "");
  } else {
    for (const technique of report.mitre) {
      push(
        `### ${technique.techniqueId} — ${technique.techniqueName}`,
        "",
        `- Tactic: ${technique.tactic}`,
        `- Confidence: ${formatPct(technique.confidence)}`,
        `- AI explanation: ${technique.aiExplanation}`,
        "- Evidence:",
      );
      for (const item of technique.evidence) {
        push(`    - \`${item.artifact}\` (${item.sessionId})`);
      }
      push("");
    }
  }

  push("## Indicators of Compromise  [OBSERVED]", "");
  if (report.indicators.length === 0) {
    push("No indicators were extracted.", "");
  } else {
    push(
      "| Type | Indicator | Confidence | Source | Last seen |",
      "| --- | --- | --- | --- | --- |",
    );
    for (const indicator of report.indicators) {
      push(
        `| ${indicator.type} | \`${indicator.value}\` | ${formatPct(indicator.confidence)} | ${indicator.source} | ${formatDateTime(indicator.lastSeen)} |`,
      );
    }
    push("");
  }

  push(
    "## Threat Assessment  [AI INFERENCE]",
    "",
    `- Level: ${report.threatAssessment.level.toUpperCase()}`,
    `- Confidence: ${formatPct(report.threatAssessment.confidence)}`,
    "",
    report.threatAssessment.narrative,
    "",
  );

  push("## Recommended Actions  [AI INFERENCE]", "");
  for (const action of report.recommendedActions) {
    push(`- **${action.priority}** ${action.action} — ${action.rationale}`);
  }
  push("");

  return lines.join("\n");
}
