import { AlertTriangle } from "lucide-react";
import { EventDisclosure } from "./EventDisclosure";
import { RemediationPatch } from "./RemediationPatch";
import { Mono, ProvenanceBadge, RiskBadge } from "@/components/common";
import { CHARACTERISTIC_LABELS, SEVERITY_AS_RISK } from "@/services/evaluation";
import type {
  EvaluationCharacteristic,
  EvaluationEvidence,
  EvaluationFinding,
  EvaluationRemediation,
  EvaluationRun,
} from "@/types";

/**
 * Findings grouped by the characteristic they were raised against, each with
 * the evidence it rests on.
 *
 * Nothing here is decorative. A finding's evidence carries an `esEventId`,
 * `chainStepId` or `probeResultId`, and each is resolved against the thing it
 * points at -- the event index, or this run's own arrays. Where a citation
 * cannot be resolved it says so, because an unresolvable claim rendered as a
 * grounded one is the failure this whole surface exists to prevent.
 */
export function EvaluationFindings({
  run,
  remediation,
}: {
  run: EvaluationRun;
  /**
   * Fixes keyed by `findingKey`, or undefined while they are still loading or
   * could not be fetched.
   *
   * Undefined renders NOTHING rather than an empty state. "We have not asked
   * yet" and "there is no fix" are different claims, and showing the second
   * for the first would report a defect as unfixable on the strength of a
   * pending request.
   */
  remediation?: Map<string, EvaluationRemediation> | undefined;
}) {
  if (run.findings.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        This run raised no findings. That is not the same as a clean result — see the module
        statuses above for what was actually measured.
      </p>
    );
  }

  const groups = new Map<EvaluationCharacteristic, EvaluationFinding[]>();
  for (const finding of run.findings) {
    const existing = groups.get(finding.characteristic);
    if (existing) existing.push(finding);
    else groups.set(finding.characteristic, [finding]);
  }

  return (
    <div className="space-y-4">
      {[...groups.entries()].map(([characteristic, findings]) => (
        <section key={characteristic}>
          <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.08em] text-foreground/80">
            <AlertTriangle className="size-3.5 text-muted-foreground" aria-hidden />
            {CHARACTERISTIC_LABELS[characteristic]}
            <span className="font-mono text-[10px] font-normal text-muted-foreground">
              {findings.length}
            </span>
          </h3>
          <ul className="space-y-2">
            {findings.map((finding) => {
              const fix = remediation?.get(finding.findingKey);
              return (
                <li
                  key={finding.id}
                  className="rounded-md border border-border bg-background/40 px-3 py-2.5"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <RiskBadge level={SEVERITY_AS_RISK[finding.severity]} />
                    <ProvenanceBadge
                      kind={finding.source === "evaluator" ? "AI INFERENCE" : "CORRELATED"}
                    />
                    <Mono tone="muted" className="text-[10px]">
                      {finding.source}
                    </Mono>
                  </div>
                  <p className="mt-2 text-sm leading-relaxed text-foreground/90">
                    {finding.finding}
                  </p>
                  {finding.recommendation ? (
                    <p className="mt-1.5 border-l-2 border-border pl-2.5 text-xs leading-relaxed text-muted-foreground">
                      {finding.recommendation}
                    </p>
                  ) : fix ? null : (
                    // Only when nothing else says anything. With a fix on screen
                    // this line would contradict it; without one it is still the
                    // accurate statement it always was.
                    <p className="mt-1.5 text-xs italic text-muted-foreground/70">
                      No recommendation was attached to this finding.
                    </p>
                  )}
                  {fix ? <RemediationPatch remediation={fix} /> : null}
                  <div className="mt-2.5 border-t border-border/70 pt-2">
                    <p className="label-caps mb-1.5">Evidence</p>
                    <EvidenceList evidence={finding.evidence} run={run} />
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </div>
  );
}

/** Resolves each citation against the thing it actually points at. */
function EvidenceList({ evidence, run }: { evidence: EvaluationEvidence[]; run: EvaluationRun }) {
  if (evidence.length === 0) {
    return (
      <p className="text-xs italic text-muted-foreground">
        No evidence was attached to this finding, so nothing here is resolvable.
      </p>
    );
  }

  return (
    <ul className="space-y-1.5">
      {evidence.map((item, index) => (
        <li
          key={`${item.kind}-${item.esEventId ?? item.chainStepId ?? item.probeResultId ?? index}`}
          className="rounded border border-border/70 bg-background/50 px-2 py-1.5"
        >
          <EvidenceItem evidence={item} run={run} />
        </li>
      ))}
    </ul>
  );
}

function EvidenceItem({ evidence, run }: { evidence: EvaluationEvidence; run: EvaluationRun }) {
  if (evidence.kind === "event" && evidence.esEventId !== null) {
    return (
      <div className="min-w-0">
        <p className="label-caps mb-1">Honeypot event</p>
        <EventDisclosure eventId={evidence.esEventId} />
      </div>
    );
  }

  if (evidence.kind === "probe" && evidence.probeResultId !== null) {
    const probe = run.probeResults.find((result) => result.id === evidence.probeResultId);
    if (!probe) {
      return (
        <Unresolvable
          kind="Probe result"
          id={evidence.probeResultId}
          reason="No probe with this id is present on this run, so the citation cannot be checked."
        />
      );
    }
    return (
      <div className="min-w-0">
        <p className="label-caps mb-1">Probe result</p>
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <Mono className="text-[11px]">{probe.probeId}</Mono>
          <Mono tone="muted" className="text-[11px]">
            {probe.module}
          </Mono>
          <Mono tone="muted" className="text-[11px]">
            {probe.target}
          </Mono>
          <span className="font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground">
            {probe.factStatus}
          </span>
        </div>
        <p className="mt-1 break-all font-mono text-[11px] text-foreground/90">
          {probe.establishes ?? "— establishes nothing —"}
          {" = "}
          {probe.value ?? "— no value observed —"}
        </p>
      </div>
    );
  }

  if (evidence.kind === "chain_step" && evidence.chainStepId !== null) {
    // The backend's ChainStepOut carries no id field, so there is nothing on
    // `run.chainSteps` to match this row id against. Say so rather than
    // guessing at a step and presenting the guess as the cited one.
    return (
      <Unresolvable
        kind="Chain step"
        id={evidence.chainStepId}
        reason="Chain steps are served without their row ids, so this citation cannot be resolved locally. The chain-step table below carries each step's own Cowrie event id, which does resolve."
      />
    );
  }

  return (
    <Unresolvable
      kind={evidence.kind}
      id="—"
      reason="This citation carries no id for its kind, so there is nothing to resolve."
    />
  );
}

function Unresolvable({ kind, id, reason }: { kind: string; id: string; reason: string }) {
  return (
    <div className="min-w-0">
      <p className="label-caps mb-1 text-medium">{kind} — unresolved</p>
      <Mono tone="muted" className="block truncate text-[11px]">
        {id}
      </Mono>
      <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{reason}</p>
    </div>
  );
}
