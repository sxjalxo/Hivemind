import { Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  Bot,
  ChevronRight,
  ListChecks,
  RotateCcw,
  Sparkles,
  Telescope,
} from "lucide-react";
import { useState } from "react";
import { AnalysisProgress } from "./AnalysisProgress";
import { EvidenceList } from "./EvidenceList";
import {
  ConfidenceBar,
  DemoDataBadge,
  ErrorState,
  MitreBadge,
  Mono,
  Panel,
  ProvenanceBadge,
  RiskBadge,
  RiskScoreMeter,
  SERVICE_ERRORS,
} from "@/components/common";
import { SEVERITY_COLOR } from "@/components/charts/palette";
import { Button } from "@/components/ui/button";
import { useAnalysisRun } from "@/hooks/useAnalysisRun";
import { RunActor } from "@/components/evaluation/RunActor";
import { useAdminForHoneypot } from "@/hooks/useAdminFor";
import { isDemoMode } from "@/services";
import { formatDuration } from "@/utils/format";
import { cn } from "@/lib/utils";
import type { EvidenceRef, SessionAnalysis } from "@/types";

/**
 * The AI ANALYZE surface.
 *
 * The panel is deliberately styled apart from the raw-telemetry panels, and
 * every conclusion carries its confidence, its evidence and its source session
 * so an LLM label is never mistaken for an observation.
 */
export function AiAnalysisPanel({
  sessionId,
  honeypotId,
  existing,
  onTechniqueSelect,
}: {
  sessionId: string;
  /** Which honeypot this session belongs to. Roles are per-honeypot,
   *  so the button asks about THIS one, not about admin-anywhere. */
  honeypotId: string;
  /** A previously stored analysis for this session, if the backend has one. */
  existing?: SessionAnalysis | null;
  onTechniqueSelect?: (techniqueId: string) => void;
}) {
  const { analysis, isRunning, error, run, analyze, reset } = useAnalysisRun(sessionId);
  // Presentation only: the backend refuses a viewer regardless. Offering
  // a button that is certain to 403 is just a worse way to say no.
  const canAnalyze = useAdminForHoneypot(honeypotId);
  const result = analysis ?? existing ?? null;

  return (
    <section className="overflow-hidden rounded-xl border border-ai/30 bg-ai/[0.04] shadow-panel">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-ai/25 bg-ai/[0.06] px-4 py-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-ai/40 bg-ai/15">
            <Bot className="size-4 text-ai" aria-hidden />
          </span>
          <div className="min-w-0">
            <h2 className="text-sm font-semibold tracking-tight text-foreground">AI Analysis</h2>
            <p className="text-xs text-muted-foreground">
              LLM interpretation of this session, mapped back to recorded evidence.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {result ? (
            <Button variant="outline" size="sm" onClick={reset} disabled={isRunning}>
              <RotateCcw className="size-3.5" />
              Re-run
            </Button>
          ) : null}
          <Button
            size="sm"
            onClick={analyze}
            disabled={isRunning || !canAnalyze.allowed}
            title={canAnalyze.title}
            className="bg-ai text-ai-foreground hover:bg-ai/90"
          >
            <Sparkles className={cn("size-3.5", isRunning && "animate-pulse")} />
            {isRunning ? "Analysing..." : "AI Analyze"}
          </Button>
        </div>
      </header>

      <div className="p-4">
        {isRunning ? (
          <RunningView
            stageIndex={run.stageIndex}
            indeterminate={run.indeterminate}
            metrics={run.metrics}
          />
        ) : error ? (
          <ErrorState
            title={SERVICE_ERRORS.ai.title}
            description={SERVICE_ERRORS.ai.description}
            onRetry={analyze}
          />
        ) : result ? (
          <AnalysisResult analysis={result} onTechniqueSelect={onTechniqueSelect} />
        ) : (
          <IdleView onAnalyze={analyze} />
        )}
      </div>
    </section>
  );
}

function IdleView({ onAnalyze }: { onAnalyze: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 px-4 py-10 text-center">
      <span className="flex size-10 items-center justify-center rounded-lg border border-ai/30 bg-ai/10">
        <Telescope className="size-4 text-ai" aria-hidden />
      </span>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">This session has not been analysed.</p>
        <p className="mx-auto max-w-md text-xs text-muted-foreground">
          Run the analysis pipeline to classify attacker behaviour, extract indicators and map
          ATT&amp;CK techniques against the recorded commands.
        </p>
      </div>
      <Button size="sm" onClick={onAnalyze} className="bg-ai text-ai-foreground hover:bg-ai/90">
        <Sparkles className="size-3.5" />
        AI Analyze
      </Button>
    </div>
  );
}

function RunningView({
  stageIndex,
  indeterminate,
  metrics,
}: {
  stageIndex: number | null;
  indeterminate: boolean;
  metrics: {
    progressPct: number;
    eventsProcessed: number;
    commandsAnalyzed: number;
    techniquesDetected: number;
    iocsExtracted: number;
  } | null;
}) {
  return (
    <div className="grid gap-5 md:grid-cols-2">
      <div>
        <div className="mb-3 flex items-center gap-2">
          <span className="font-mono text-xs uppercase tracking-[0.08em] text-ai">
            Analysing attacker session
          </span>
          {isDemoMode ? <DemoDataBadge /> : null}
        </div>

        <div className="mb-3 h-1 overflow-hidden rounded-full bg-muted">
          {indeterminate ? (
            <div className="h-full w-1/3 rounded-full bg-ai scan-sweep" />
          ) : (
            <div
              className="h-full rounded-full bg-ai transition-[width] duration-500"
              style={{ width: `${metrics?.progressPct ?? 0}%` }}
            />
          )}
        </div>

        <AnalysisProgress activeIndex={stageIndex ?? -1} />

        {indeterminate ? (
          <p className="mt-3 border-t border-border pt-2.5 text-[11px] leading-relaxed text-muted-foreground">
            The backend is not reporting per-stage progress, so these stages show the expected
            pipeline rather than live status.
          </p>
        ) : null}
      </div>

      <dl className="grid grid-cols-2 gap-2 self-start">
        {[
          { label: "Events processed", value: metrics?.eventsProcessed },
          { label: "Commands analysed", value: metrics?.commandsAnalyzed },
          { label: "Techniques detected", value: metrics?.techniquesDetected },
          { label: "IOCs extracted", value: metrics?.iocsExtracted },
        ].map((metric) => (
          <div
            key={metric.label}
            className="rounded-md border border-border bg-background/40 p-2.5"
          >
            <dt className="label-caps truncate">{metric.label}</dt>
            <dd className="mt-1 font-mono text-lg font-semibold tabular-nums text-foreground">
              {metric.value ?? "--"}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function AnalysisResult({
  analysis,
  onTechniqueSelect,
}: {
  analysis: SessionAnalysis;
  onTechniqueSelect?: ((techniqueId: string) => void) | undefined;
}) {
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <ProvenanceBadge kind="AI INFERENCE" />
        <Mono tone="muted" className="text-[11px]">
          {analysis.model}
        </Mono>
        <span className="text-muted-foreground/50">/</span>
        <Mono tone="muted" className="text-[11px]">
          {analysis.analysisType}
        </Mono>
        <span className="text-muted-foreground/50">/</span>
        <Mono tone="muted" className="text-[11px]">
          {analysis.durationSeconds.toFixed(1)}s
        </Mono>
        {isDemoMode ? <DemoDataBadge className="ml-auto" /> : null}
      </div>

      <div className="grid gap-4 rounded-lg border border-border bg-background/40 p-4 sm:grid-cols-3">
        <div>
          <p className="label-caps">Classification</p>
          <p className="mt-1.5 text-sm font-semibold text-foreground">{analysis.classification}</p>
        </div>
        <div>
          <p className="label-caps">Confidence</p>
          <div className="mt-1.5">
            <ConfidenceBar value={analysis.confidence} compact />
          </div>
        </div>
        <div>
          <p className="label-caps">Risk score</p>
          <div className="mt-1">
            <RiskScoreMeter score={analysis.riskScore} />
          </div>
        </div>
      </div>

      <blockquote className="border-l-2 border-ai/50 bg-ai/[0.05] px-3.5 py-2.5">
        <p className="label-caps mb-1">Behaviour summary</p>
        <p className="text-sm leading-relaxed text-foreground/90">{analysis.behaviorSummary}</p>
      </blockquote>

      <div className="grid gap-4 lg:grid-cols-2">
        <SubSection title="Observed Behaviour" icon={Telescope}>
          <ul className="space-y-2">
            {analysis.observedBehavior.map((item) => (
              <EvidenceDisclosure key={item.label} label={item.label} evidence={item.evidence} />
            ))}
          </ul>
        </SubSection>

        <SubSection title="Suspicious Indicators" icon={AlertTriangle}>
          <ul className="space-y-2">
            {analysis.suspiciousIndicators.map((item) => (
              <EvidenceDisclosure
                key={item.label}
                label={item.label}
                evidence={item.evidence}
                accent={SEVERITY_COLOR[item.severity]}
                trailing={<RiskBadge level={item.severity} />}
              />
            ))}
          </ul>
        </SubSection>
      </div>

      {analysis.techniques.length > 0 ? (
        <SubSection title="Mapped ATT&CK Techniques" icon={Bot}>
          <div className="flex flex-wrap gap-1.5">
            {analysis.techniques.map((technique) => (
              <MitreBadge
                key={technique.techniqueId}
                techniqueId={technique.techniqueId}
                name={technique.techniqueName}
                observed={technique.observed}
                {...(onTechniqueSelect
                  ? { onClick: () => onTechniqueSelect(technique.techniqueId) }
                  : {})}
              />
            ))}
          </div>
          <p className="mt-2 text-[11px] text-muted-foreground">
            Highlighted techniques are rule-backed and appear with their evidence in the ATT&amp;CK
            panel below. Muted ones are LLM proposals: they are listed here only, and no ATT&amp;CK
            identifier is written back to the event index for them.
          </p>
        </SubSection>
      ) : null}

      <SubSection title="Recommended Actions" icon={ListChecks}>
        <ol className="space-y-2">
          {analysis.recommendedActions.map((action) => (
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
      </SubSection>

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3">
        <span className="text-[11px] text-muted-foreground">
          Analysis <Mono className="text-[11px]">{analysis.id}</Mono> of session{" "}
          <Mono className="text-[11px]">{analysis.sessionId}</Mono>, run by{" "}
          <RunActor startedBy={analysis.startedBy} startedByLabel={analysis.startedByLabel} />
        </span>
        <Link
          to="/reports"
          search={{ session: analysis.sessionId }}
          className="inline-flex items-center gap-1 font-mono text-[11px] uppercase tracking-[0.08em] text-primary hover:underline"
        >
          Generate report
          <ChevronRight className="size-3" aria-hidden />
        </Link>
      </div>
    </div>
  );
}

function SubSection({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: typeof Bot;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.08em] text-foreground/80">
        <Icon className="size-3.5 text-muted-foreground" aria-hidden />
        {title}
      </h3>
      {children}
    </div>
  );
}

/** A single AI claim with its supporting telemetry one click away. */
function EvidenceDisclosure({
  label,
  evidence,
  accent,
  trailing,
}: {
  label: string;
  evidence: EvidenceRef[];
  accent?: string;
  trailing?: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);

  return (
    <li className="rounded-md border border-border bg-background/40">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-accent/25"
      >
        <span
          className="size-1.5 shrink-0 rounded-full"
          style={{ backgroundColor: accent ?? "var(--color-ai)" }}
          aria-hidden
        />
        <span className="min-w-0 flex-1 truncate text-sm text-foreground/90">{label}</span>
        {trailing}
        <span className="shrink-0 font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground">
          {evidence.length} evidence
        </span>
        <ChevronRight
          className={cn(
            "size-3.5 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-90",
          )}
          aria-hidden
        />
      </button>
      {open ? (
        <div className="border-t border-border px-3 py-2.5">
          <p className="label-caps mb-1.5">Supporting telemetry</p>
          <EvidenceList evidence={evidence} dense />
        </div>
      ) : null}
    </li>
  );
}
