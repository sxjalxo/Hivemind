import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Radar } from "lucide-react";
import { EmptyState, PageHeader, Panel } from "@/components/common";
import { SensorEvaluationsPanel } from "@/components/sensor/SensorEvaluationsPanel";
import { SensorIdentityPanel } from "@/components/sensor/SensorIdentityPanel";
import { SensorTechniquesPanel } from "@/components/sensor/SensorTechniquesPanel";
import { SensorTrafficPanel } from "@/components/sensor/SensorTrafficPanel";
import { cn } from "@/lib/utils";
import { ApiError } from "@/services";
import { sensorQueries } from "@/services/queries";

export const Route = createFileRoute("/honeypots/$honeypotId")({
  component: SensorPage,
});

/** Day windows for traffic and techniques; the backend accepts 1..90. */
const WINDOWS = [7, 30, 90];

function SensorPage() {
  const { honeypotId } = Route.useParams();
  const [days, setDays] = useState(30);
  const profile = useQuery(sensorQueries.profile(honeypotId));

  // The API answers 404 both for a sensor that does not exist and for one this caller may not read.
  if (profile.error instanceof ApiError && profile.error.status === 404) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Panel>
          <EmptyState
            icon={Radar}
            title="No such sensor, or you may not see it."
            description={honeypotId}
          />
        </Panel>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <BackLink />

      <PageHeader
        title={profile.data?.name ?? honeypotId}
        subtitle="What this sensor is, what it has been disguised as and when, and what it has drawn since."
        actions={
          <div className="flex items-center gap-1" role="group" aria-label="Window">
            {WINDOWS.map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => setDays(option)}
                aria-pressed={days === option}
                className={cn(
                  "rounded border px-2 py-1 font-mono text-[11px] uppercase tracking-[0.08em] transition-colors",
                  days === option
                    ? "border-primary/50 bg-primary/12 text-primary"
                    : "border-border text-muted-foreground hover:text-foreground",
                )}
              >
                {option}d
              </button>
            ))}
          </div>
        }
      />

      <SensorIdentityPanel id={honeypotId} />
      <SensorTrafficPanel id={honeypotId} days={days} />
      <SensorTechniquesPanel id={honeypotId} days={days} />
      <SensorEvaluationsPanel id={honeypotId} />
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/honeypots"
      className="inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.08em] text-muted-foreground transition-colors hover:text-foreground"
    >
      <ArrowLeft className="size-3.5" aria-hidden />
      Back to honeypots
    </Link>
  );
}
