import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Database, Lock, Server, ShieldCheck } from "lucide-react";
import {
  DemoDataBadge,
  InlineNotice,
  Mono,
  PageHeader,
  Panel,
  StatusRow,
} from "@/components/common";
import { Skeleton } from "@/components/ui/skeleton";
import { systemStatusQuery } from "@/services/honeypots";
import { API_BASE_URL, isDemoMode } from "@/services";

export const Route = createFileRoute("/settings")({
  component: SettingsPage,
});

function SettingsPage() {
  const status = useQuery(systemStatusQuery());

  return (
    <div className="space-y-5">
      <PageHeader
        title="Settings"
        subtitle="Where this frontend gets its data, and what it deliberately does not hold."
        meta={isDemoMode ? <DemoDataBadge /> : null}
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Data source" description="The single switch between demo data and FastAPI.">
          <dl className="space-y-3">
            <Row label="Active provider">
              <Mono className="text-[13px]">{isDemoMode ? "DemoProvider" : "FastAPIProvider"}</Mono>
            </Row>
            <Row label="API base URL">
              <Mono className="text-[13px]">{API_BASE_URL}</Mono>
            </Row>
            <Row label="Mode">
              <span className="text-sm text-foreground/90">
                {isDemoMode ? "Demo — synthetic dataset" : "Live — backend responses"}
              </span>
            </Row>
          </dl>

          <InlineNotice tone={isDemoMode ? "warn" : "info"} icon={Server} className="mt-4">
            {isDemoMode ? (
              <>
                Demo mode is active because <Mono className="text-[11px]">VITE_API_BASE_URL</Mono>{" "}
                is unset. Everything you see is synthetic and labelled as such. Set that variable
                and reload to route every request through FastAPI — no component changes needed.
              </>
            ) : (
              <>
                All data on this instance comes from the configured FastAPI backend. Demo fixtures
                are not loaded.
              </>
            )}
          </InlineNotice>
        </Panel>

        <Panel title="Service health" description="Reported by GET /api/status.">
          {status.isPending ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }, (_, index) => (
                <Skeleton key={index} className="h-4 w-full" />
              ))}
            </div>
          ) : status.isError ? (
            <InlineNotice tone="critical">The backend status endpoint is unreachable.</InlineNotice>
          ) : (
            <div className="space-y-0.5">
              {status.data.map((service) => (
                <StatusRow key={service.id} status={service} />
              ))}
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Security posture" description="Deliberate constraints on this frontend.">
        <ul className="space-y-3">
          <Posture
            icon={Lock}
            title="No infrastructure credentials in the browser"
            detail="Elasticsearch and Ollama credentials live only on the backend. This app holds a base URL and nothing else."
          />
          <Posture
            icon={Database}
            title="Elasticsearch is never queried directly"
            detail="Log Explorer sends its filters to FastAPI, which owns the query and the index mapping."
          />
          <Posture
            icon={ShieldCheck}
            title="AI output is always labelled"
            detail="Model conclusions carry AI INFERENCE with their confidence and evidence; recorded telemetry carries OBSERVED. The UI never blurs the two."
          />
          <Posture
            icon={Server}
            title="The LLM is not hardcoded"
            detail="Model name, analysis type and timing come from the backend for every run, so swapping the local model requires no frontend change."
          />
        </ul>
      </Panel>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-border/60 pb-2.5 last:border-0">
      <dt className="label-caps">{label}</dt>
      <dd className="min-w-0 truncate text-right">{children}</dd>
    </div>
  );
}

function Posture({
  icon: Icon,
  title,
  detail,
}: {
  icon: typeof Lock;
  title: string;
  detail: string;
}) {
  return (
    <li className="flex items-start gap-3">
      <span className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-md border border-border bg-muted/40">
        <Icon className="size-3.5 text-muted-foreground" aria-hidden />
      </span>
      <span className="min-w-0">
        <span className="block text-sm font-medium text-foreground">{title}</span>
        <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">{detail}</span>
      </span>
    </li>
  );
}
