import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, FileText, Grid3x3, Radar, User } from "lucide-react";
import { useState } from "react";
import { AiAnalysisPanel } from "@/components/session/AiAnalysisPanel";
import { AnalysisStateChip } from "@/components/session/AnalysisStateChip";
import { LogViewer } from "@/components/session/LogViewer";
import { SessionTimeline } from "@/components/session/SessionTimeline";
import { TechniqueDrawer } from "@/components/mitre/TechniqueDrawer";
import {
  ClassificationChain,
  CopyableMono,
  DemoDataBadge,
  EmptyState,
  ErrorState,
  LoadingState,
  MitreBadge,
  Mono,
  Panel,
  PageHeader,
  ProvenanceBadge,
  RiskBadge,
  RiskScoreMeter,
  SERVICE_ERRORS,
} from "@/components/common";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { isDemoMode } from "@/services";
import { formatDateTime, formatDuration, formatPct } from "@/utils/format";
import type { MitreTechnique } from "@/types";
import { analysisQueries, mitreCoverageQuery, sessionQueries } from "@/services/queries";

export const Route = createFileRoute("/sessions/$sessionId")({
  component: SessionInvestigationPage,
});

function SessionInvestigationPage() {
  const { sessionId } = Route.useParams();
  const [technique, setTechnique] = useState<MitreTechnique | null>(null);

  const session = useQuery(sessionQueries.detail(sessionId));
  const timeline = useQuery(sessionQueries.timeline(sessionId));
  const events = useQuery(sessionQueries.events(sessionId));
  const mitre = useQuery(mitreCoverageQuery(sessionId));
  const history = useQuery(analysisQueries.history());

  const storedAnalysis =
    history.data?.find((item) => item.sessionId === sessionId && item.status === "completed") ??
    null;

  const openTechnique = (techniqueId: string) => {
    const match = mitre.data?.techniques.find((item) => item.id === techniqueId);
    if (match) setTechnique(match);
  };

  if (session.isPending) return <LoadingState message="Loading session telemetry..." />;

  if (session.isError) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Panel>
          <ErrorState
            title="Session unavailable"
            error={session.error}
            description={SERVICE_ERRORS.api.description}
            onRetry={() => void session.refetch()}
          />
        </Panel>
      </div>
    );
  }

  const data = session.data;
  const observedTechniques = mitre.data?.techniques.filter((item) => item.observed) ?? [];
  /** Whether a stored analysis is what `riskScore` and `risk` are reporting. */
  const analysed = data.analysisState === "completed";

  return (
    <div className="space-y-5">
      <BackLink />

      <PageHeader
        title={`Session ${data.id}`}
        subtitle={`${data.protocol} session against ${data.honeypotName}, ${data.commandCount} commands over ${formatDuration(data.durationSeconds)}.`}
        meta={
          <>
            <ProvenanceBadge kind="OBSERVED" />
            <AnalysisStateChip state={data.analysisState} />
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
        actions={
          <>
            <Button variant="outline" size="sm" asChild>
              <Link to="/attackers/$ip" params={{ ip: data.attackerIp }}>
                <User className="size-3.5" />
                Attacker profile
              </Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/reports" search={{ session: data.id }}>
                <FileText className="size-3.5" />
                Report
              </Link>
            </Button>
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-4">
        <Panel className="lg:col-span-1" title="Risk score">
          <RiskScoreMeter score={data.riskScore} />
          <div className="mt-3 flex items-center gap-2">
            <RiskBadge level={data.risk} size="md" />
            {analysed ? <ProvenanceBadge kind="AI INFERENCE" /> : null}
          </div>
          {/* This number is `analysis.risk_score`, which `get_session` copies
              onto the session -- there is no deterministic scorer behind it.
              It comes from the model's JSON, is explicitly NOT evidence-gated
              (see the note in `services/compaction.py`), and moves between
              runs of the same session. Captioning it as a pre-LLM measurement,
              as this panel once did, was the one mislabel this project cannot
              afford: it presented a model's opinion as an observation. */}
          <p className="mt-3 border-t border-border pt-2.5 text-[11px] leading-relaxed text-muted-foreground">
            {analysed
              ? "Proposed by the model in the latest analysis — not measured from telemetry. It is not evidence-gated and can differ between runs of the same session."
              : "Not established. The session has not been analysed, so nothing has scored it; this reads informational because the question is unanswered, not because the session is harmless."}
          </p>
        </Panel>

        <Panel className="lg:col-span-3" title="Session facts">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 md:grid-cols-4">
            <Fact label="Attacker IP">
              <Link
                to="/attackers/$ip"
                params={{ ip: data.attackerIp }}
                className="font-mono text-[13px] text-foreground hover:text-primary hover:underline"
              >
                {data.attackerIp}
              </Link>
            </Fact>
            <Fact label="Honeypot">
              <span className="flex items-center gap-1.5 text-sm text-foreground/90">
                <Radar className="size-3.5 text-muted-foreground" aria-hidden />
                {data.honeypotName}
              </span>
            </Fact>
            <Fact label="Protocol">
              <Mono className="text-[13px]">{data.protocol}</Mono>
            </Fact>
            <Fact label="Ports">
              <Mono className="text-[13px]">
                {data.sourcePort ?? "unknown"} &rarr; {data.destinationPort ?? "unknown"}
              </Mono>
            </Fact>
            <Fact label="Started">
              <Mono className="text-[13px]">{formatDateTime(data.startedAt)}</Mono>
            </Fact>
            <Fact label="Duration">
              <Mono className="text-[13px]">{formatDuration(data.durationSeconds)}</Mono>
            </Fact>
            <Fact label="Commands">
              <Mono className="text-[13px]">{data.commandCount}</Mono>
            </Fact>
            <Fact label="Username">
              {data.username ? (
                <CopyableMono value={data.username} className="text-[13px]" />
              ) : (
                <span className="text-xs text-muted-foreground">Not captured</span>
              )}
            </Fact>
            <div className="col-span-2 md:col-span-4">
              <dt className="label-caps">Classification chain</dt>
              <dd className="mt-1.5">
                <ClassificationChain chain={data.classificationChain} />
              </dd>
            </div>
          </dl>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-5">
        <Panel
          className="xl:col-span-2"
          title="Attack Timeline"
          description="Chronological record of what the attacker did."
        >
          {timeline.isPending ? (
            <Skeleton className="h-[320px] w-full" />
          ) : timeline.isError ? (
            <ErrorState
              title={SERVICE_ERRORS.elasticsearch.title}
              description={SERVICE_ERRORS.elasticsearch.description}
              onRetry={() => void timeline.refetch()}
            />
          ) : timeline.data.length === 0 ? (
            <EmptyState title="No timeline events were recorded for this session." />
          ) : (
            <SessionTimeline
              events={timeline.data}
              onSelect={(event) => event.techniqueId && openTechnique(event.techniqueId)}
            />
          )}
        </Panel>

        <Panel
          className="xl:col-span-3"
          title="Session Log"
          description="Commands and captured output exactly as recorded by the honeypot."
          bodyClassName="p-0"
        >
          {events.isPending ? (
            <div className="p-4">
              <Skeleton className="h-[320px] w-full" />
            </div>
          ) : events.isError ? (
            <ErrorState
              title={SERVICE_ERRORS.elasticsearch.title}
              description={SERVICE_ERRORS.elasticsearch.description}
              onRetry={() => void events.refetch()}
            />
          ) : events.data.length === 0 ? (
            <EmptyState title="No honeypot events found for this session." />
          ) : (
            <div className="max-h-[520px]">
              <LogViewer events={events.data} />
            </div>
          )}
        </Panel>
      </div>

      <AiAnalysisPanel
        sessionId={sessionId}
        honeypotId={session.data.honeypotId}
        existing={storedAnalysis}
        onTechniqueSelect={openTechnique}
      />

      <Panel
        title="MITRE ATT&CK Techniques"
        description="Techniques associated with this session, each backed by its own evidence."
        actions={
          <Link
            to="/mitre"
            search={{ session: sessionId }}
            className="inline-flex items-center gap-1 font-mono text-[11px] uppercase tracking-[0.08em] text-primary hover:underline"
          >
            <Grid3x3 className="size-3" aria-hidden />
            Full matrix
          </Link>
        }
      >
        {mitre.isPending ? (
          <Skeleton className="h-24 w-full" />
        ) : mitre.isError ? (
          <ErrorState
            title="ATT&CK mapping unavailable"
            error={mitre.error}
            onRetry={() => void mitre.refetch()}
          />
        ) : observedTechniques.length === 0 ? (
          <EmptyState
            icon={Grid3x3}
            title="No ATT&CK techniques have been associated with this session."
            description="Run the AI analysis to map recorded behaviour onto the ATT&CK matrix."
          />
        ) : (
          <ul className="grid gap-2 md:grid-cols-2">
            {observedTechniques.map((item) => (
              <li key={item.id}>
                <button
                  type="button"
                  onClick={() => setTechnique(item)}
                  className="w-full rounded-md border border-border bg-background/40 px-3 py-2.5 text-left transition-colors hover:border-primary/40 hover:bg-accent/30"
                >
                  <span className="flex items-center gap-2">
                    <MitreBadge techniqueId={item.id} />
                    <span className="min-w-0 flex-1 truncate text-sm text-foreground/90">
                      {item.name}
                    </span>
                    {item.confidence !== undefined ? (
                      <span className="shrink-0 font-mono text-[11px] tabular-nums text-muted-foreground">
                        {formatPct(item.confidence)}
                      </span>
                    ) : null}
                  </span>
                  <span className="mt-1 flex items-center gap-2">
                    <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                      {item.tactic}
                    </span>
                    <span className="font-mono text-[10px] text-muted-foreground">
                      {item.evidence.length} evidence
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <TechniqueDrawer
        technique={technique}
        open={technique !== null}
        onOpenChange={(open) => !open && setTechnique(null)}
      />
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/sessions"
      className="inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.08em] text-muted-foreground transition-colors hover:text-foreground"
    >
      <ArrowLeft className="size-3.5" aria-hidden />
      All sessions
    </Link>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="label-caps">{label}</dt>
      <dd className="mt-1 min-w-0 truncate">{children}</dd>
    </div>
  );
}
