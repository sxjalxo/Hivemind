import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Globe, MapPin, Radar } from "lucide-react";
import { AttackPatternGraph, SimilarityList } from "@/components/attacker/AttackPatternGraph";
import {
  CopyableMono,
  DemoDataBadge,
  EmptyState,
  ErrorState,
  InlineNotice,
  LoadingState,
  MitreBadge,
  Mono,
  PageHeader,
  Panel,
  ProvenanceBadge,
  RiskBadge,
  RiskScoreMeter,
} from "@/components/common";
import { isDemoMode } from "@/services";
import { formatBytes, formatDateTime } from "@/utils/format";
import { sessionQueries } from "@/services/queries";

export const Route = createFileRoute("/attackers/$ip")({
  component: AttackerProfilePage,
});

function AttackerProfilePage() {
  const { ip } = Route.useParams();
  const navigate = useNavigate();
  const { data, isPending, isError, error, refetch } = useQuery(sessionQueries.attacker(ip));

  if (isPending) return <LoadingState message="Loading attacker profile..." />;

  if (isError) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Panel>
          <ErrorState
            title="Attacker profile unavailable"
            description={`No correlated profile exists for ${ip}.`}
            error={error}
            onRetry={() => void refetch()}
          />
        </Panel>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <BackLink />

      <PageHeader
        title="Attacker Profile"
        subtitle={`Correlated activity for ${data.ip} across the honeypot fleet.`}
        meta={
          <>
            <ProvenanceBadge kind="CORRELATED" />
            <span className="label-caps">{data.behaviorLabel}</span>
            {isDemoMode ? <DemoDataBadge /> : null}
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-4">
        <Panel className="lg:col-span-1" title="Assessed risk">
          <RiskScoreMeter score={data.riskScore} />
          <div className="mt-3">
            <RiskBadge level={data.risk} size="md" />
          </div>
          <p className="mt-3 border-t border-border pt-2.5 text-[11px] leading-relaxed text-muted-foreground">
            Aggregated from {data.sessions} correlated{" "}
            {data.sessions === 1 ? "session" : "sessions"}.
          </p>
        </Panel>

        <Panel className="lg:col-span-3" title="Identity and reach">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 md:grid-cols-4">
            <Fact label="Source IP">
              <CopyableMono value={data.ip} className="text-[13px]" />
            </Fact>
            <Fact label="Sessions">
              <Mono className="text-[13px]">{data.sessions}</Mono>
            </Fact>
            <Fact label="First seen">
              <Mono className="text-[13px]">{formatDateTime(data.firstSeen)}</Mono>
            </Fact>
            <Fact label="Last seen">
              <Mono className="text-[13px]">{formatDateTime(data.lastSeen)}</Mono>
            </Fact>
            <Fact label="Country">
              <span className="flex items-center gap-1.5 text-sm text-foreground/90">
                <MapPin className="size-3.5 text-muted-foreground" aria-hidden />
                {data.geo?.country ?? "Unresolved"}
              </span>
            </Fact>
            <Fact label="ASN">
              <Mono className="text-[13px]">{data.geo?.asn ?? "—"}</Mono>
            </Fact>
            <Fact label="Organisation">
              <span className="truncate text-sm text-foreground/90">{data.geo?.org ?? "—"}</span>
            </Fact>
            <Fact label="Behaviour">
              <span className="text-sm text-foreground/90">{data.behaviorLabel}</span>
            </Fact>
          </dl>

          {data.geo === null ? (
            <InlineNotice tone="info" icon={Globe} className="mt-4">
              Geographic enrichment is not configured on the backend, so location fields are shown
              as placeholders rather than guessed.
            </InlineNotice>
          ) : null}
        </Panel>
      </div>

      <Panel
        title="Attack Pattern"
        description="The repeatable sequence this attacker follows across sessions."
        actions={<ProvenanceBadge kind="CORRELATED" showIcon={false} />}
      >
        <AttackPatternGraph stages={data.attackPattern} />
      </Panel>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Targeted Honeypots">
          {data.targetedHoneypots.length === 0 ? (
            <EmptyState icon={Radar} title="No honeypots recorded." />
          ) : (
            <ul className="space-y-1.5">
              {data.targetedHoneypots.map((name) => (
                <li key={name} className="flex items-center gap-2 text-sm text-foreground/90">
                  <Radar className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="truncate">{name}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Techniques">
          {data.techniqueIds.length === 0 ? (
            <EmptyState title="No ATT&CK techniques associated." />
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {data.techniqueIds.map((id) => (
                <MitreBadge
                  key={id}
                  techniqueId={id}
                  onClick={() => void navigate({ to: "/mitre", search: { technique: id } })}
                />
              ))}
            </div>
          )}
        </Panel>

        <Panel
          title="Behavioural Similarity"
          description="Other sources with comparable behaviour."
        >
          <SimilarityList
            entries={data.similarity}
            complete={data.similarityComplete}
            reason={data.similarityIncompleteReason}
            onSelect={(other) => void navigate({ to: "/attackers/$ip", params: { ip: other } })}
          />
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel
          title="Commands Used"
          description="Distinct commands recorded across this attacker's sessions."
          actions={<ProvenanceBadge kind="OBSERVED" showIcon={false} />}
        >
          {data.commands.length === 0 ? (
            <EmptyState title="No commands recorded." />
          ) : (
            <ul className="space-y-1">
              {data.commands.map((command) => (
                <li key={command}>
                  <Link
                    to="/logs"
                    search={{ q: command }}
                    className="block truncate rounded border border-border bg-background/40 px-2 py-1.5 font-mono text-[12px] text-foreground/90 transition-colors hover:border-primary/40 hover:text-primary"
                  >
                    {command}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Downloaded Files"
          description="Payloads retrieved during these sessions."
          actions={<ProvenanceBadge kind="STATIC ANALYSIS" showIcon={false} />}
        >
          {data.downloadedFiles.length === 0 ? (
            <EmptyState title="No payloads were captured." />
          ) : (
            <ul className="space-y-2">
              {data.downloadedFiles.map((file) => (
                <li
                  key={file.sha256}
                  className="rounded-md border border-border bg-background/40 px-3 py-2"
                >
                  <div className="flex items-baseline justify-between gap-2">
                    <Mono className="truncate text-[13px]">{file.name}</Mono>
                    <Mono tone="muted" className="shrink-0 text-[11px]">
                      {formatBytes(file.size)}
                    </Mono>
                  </div>
                  <div className="mt-1">
                    <CopyableMono value={file.sha256} tone="muted" className="text-[11px]" />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel title="Associated Indicators">
        {data.indicatorIds.length === 0 ? (
          <EmptyState title="No indicators are linked to this attacker." />
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {data.indicatorIds.map((id) => (
              <span
                key={id}
                className="rounded border border-border bg-muted/40 px-1.5 py-1 font-mono text-[11px] text-muted-foreground"
              >
                {id}
              </span>
            ))}
          </div>
        )}
      </Panel>
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
      Back to sessions
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
