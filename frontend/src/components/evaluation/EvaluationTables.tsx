import { EventDisclosure } from "./EventDisclosure";
import { MitreBadge, Mono } from "@/components/common";
import { MODULE_STATUS_HINTS, MODULE_STATUS_LABELS } from "@/services/evaluation";
import { cn } from "@/lib/utils";
import type {
  EvaluationChainStep,
  EvaluationFactStatus,
  EvaluationModuleResult,
  EvaluationProbeResult,
} from "@/types";

/** `unknown` is excluded from scoring: it is not a failed check. */
const FACT_STATUS_STYLE: Record<EvaluationFactStatus, { className: string; hint: string }> = {
  observed: {
    className: "border-success/40 bg-success/12 text-success",
    hint: "The fact was established by observation.",
  },
  not_observed: {
    className: "border-high/40 bg-high/12 text-high",
    hint: "The step ran and the expected effect was not observed.",
  },
  unknown: {
    className: "border-border bg-muted/40 text-muted-foreground",
    hint: "Nothing was established. Excluded from scoring entirely — this is not a failed check.",
  },
};

export function FactStatusChip({ status }: { status: EvaluationFactStatus }) {
  const style = FACT_STATUS_STYLE[status];
  return (
    <span
      title={style.hint}
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-[3px] font-mono text-[10px] font-semibold uppercase tracking-[0.06em] leading-none",
        style.className,
      )}
    >
      {status}
    </span>
  );
}

/**
 * Every replayed chain step, and the evidence trail for each:
 * expected technique → command → Cowrie event → matched rule.
 *
 * The Cowrie event id is expandable into the real event, so a step's claim
 * that the honeypot recorded a command can be checked against the recording.
 */
export function ChainStepTable({ steps }: { steps: EvaluationChainStep[] }) {
  if (steps.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        This run replayed no attack chains, so it measured nothing about attack possibilities.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[900px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border">
            {[
              "Chain",
              "Step",
              "Expected technique",
              "Command",
              "Cowrie event",
              "Matched rule",
              "Fact",
            ].map((heading) => (
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
          {steps.map((step) => (
            <tr
              key={`${step.chainId}-${step.stepIndex}`}
              className="border-b border-border/60 align-top last:border-0"
            >
              <td className="whitespace-nowrap px-3 py-2">
                <Mono tone="muted" className="text-[11px]">
                  {step.chainId}
                </Mono>
              </td>
              <td className="px-3 py-2 font-mono text-[11px] tabular-nums text-muted-foreground">
                {step.stepIndex}
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <MitreBadge
                  techniqueId={step.expectedTechniqueId}
                  observed={step.factStatus === "observed"}
                />
              </td>
              <td className="max-w-[280px] px-3 py-2">
                <code className="block break-all font-mono text-[12px] text-foreground/90">
                  {step.command}
                </code>
              </td>
              <td className="max-w-[220px] px-3 py-2">
                {step.cowrieEventId ? (
                  <EventDisclosure eventId={step.cowrieEventId} />
                ) : (
                  <span
                    title="The honeypot recorded no event for this command, so there is nothing to resolve. Not a zero, and not a failed check on its own."
                    className="font-mono text-[11px] italic text-muted-foreground"
                  >
                    no event recorded
                  </span>
                )}
              </td>
              <td className="px-3 py-2">
                {step.matchedRuleId ? (
                  <Mono tone="muted" className="text-[11px]">
                    {step.matchedRuleId}
                  </Mono>
                ) : (
                  <span className="font-mono text-[11px] italic text-muted-foreground">
                    no rule matched
                  </span>
                )}
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <FactStatusChip status={step.factStatus} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The probe rows a finding's `probeResultId` resolves against. */
export function ProbeResultTable({ probes }: { probes: EvaluationProbeResult[] }) {
  if (probes.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        This run recorded no probe results, so no probe citation on it can be resolved.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[820px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border">
            {["Probe", "Module", "Target", "Establishes", "Value", "Fact", "Result id"].map(
              (heading) => (
                <th
                  key={heading}
                  className="label-caps whitespace-nowrap px-3 py-2 text-left font-normal"
                >
                  {heading}
                </th>
              ),
            )}
          </tr>
        </thead>
        <tbody>
          {probes.map((probe) => (
            <tr key={probe.id} className="border-b border-border/60 align-top last:border-0">
              <td className="whitespace-nowrap px-3 py-2">
                <Mono className="text-[11px]">{probe.probeId}</Mono>
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <Mono tone="muted" className="text-[11px]">
                  {probe.module}
                </Mono>
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <Mono tone="muted" className="text-[11px]">
                  {probe.target}
                </Mono>
              </td>
              <td className="px-3 py-2">
                {probe.establishes ? (
                  <Mono className="text-[11px]">{probe.establishes}</Mono>
                ) : (
                  <span className="font-mono text-[11px] italic text-muted-foreground">
                    establishes nothing
                  </span>
                )}
              </td>
              <td className="max-w-[280px] px-3 py-2">
                {probe.value ? (
                  <code className="block break-all font-mono text-[11px] text-foreground/90">
                    {probe.value}
                  </code>
                ) : (
                  <span className="font-mono text-[11px] italic text-muted-foreground">
                    no value observed
                  </span>
                )}
              </td>
              <td className="whitespace-nowrap px-3 py-2">
                <FactStatusChip status={probe.factStatus} />
              </td>
              <td className="px-3 py-2">
                <Mono tone="muted" className="text-[10px]">
                  {probe.id}
                </Mono>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Module outcomes. A module's status is distinct from its facts' status: a
 * module that timed out leaves facts unknown, and unknown is not negative
 * evidence against the honeypot.
 */
export function ModuleResultTable({ modules }: { modules: EvaluationModuleResult[] }) {
  if (modules.length === 0) {
    return <p className="text-xs text-muted-foreground">This run recorded no module results.</p>;
  }

  return (
    <ul className="space-y-1.5">
      {modules.map((module) => (
        <li
          key={module.module}
          className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border border-border bg-background/40 px-3 py-2"
        >
          <Mono className="text-[12px]">{module.module}</Mono>
          <span
            title={MODULE_STATUS_HINTS[module.moduleStatus]}
            className={cn(
              "inline-flex items-center rounded border px-1.5 py-[3px] font-mono text-[10px] font-semibold uppercase tracking-[0.06em] leading-none",
              module.moduleStatus === "completed"
                ? "border-success/40 bg-success/12 text-success"
                : module.moduleStatus === "skipped"
                  ? "border-border bg-muted/40 text-muted-foreground"
                  : "border-medium/40 bg-medium/12 text-medium",
            )}
          >
            {MODULE_STATUS_LABELS[module.moduleStatus]}
          </span>
          <span className="min-w-0 flex-1 text-xs text-muted-foreground">
            {module.detail ?? MODULE_STATUS_HINTS[module.moduleStatus]}
          </span>
        </li>
      ))}
    </ul>
  );
}
