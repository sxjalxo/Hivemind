import { ExternalLink } from "lucide-react";
import { EvidenceList } from "@/components/session/EvidenceList";
import { ConfidenceBar, EmptyState, Mono, ProvenanceBadge } from "@/components/common";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { formatDateTime } from "@/utils/format";
import type { MitreTechnique } from "@/types";

/**
 * Technique detail drawer.
 *
 * Confidence and the AI explanation are labelled as inference; the evidence and
 * related commands beneath them are the recorded telemetry that produced the
 * mapping. That separation is the point of this screen.
 */
export function TechniqueDrawer({
  technique,
  open,
  onOpenChange,
}: {
  technique: MitreTechnique | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        {technique ? (
          <>
            <SheetHeader className="space-y-2 text-left">
              <div className="flex flex-wrap items-center gap-2">
                <Mono className="rounded border border-primary/40 bg-primary/12 px-1.5 py-[3px] text-[11px] font-semibold text-primary">
                  {technique.id}
                </Mono>
                <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                  {technique.tactic}
                </span>
                {technique.observed ? (
                  <ProvenanceBadge kind="OBSERVED" />
                ) : (
                  <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                    Not observed
                  </span>
                )}
              </div>
              <SheetTitle className="text-base">{technique.name}</SheetTitle>
              <SheetDescription className="text-xs">
                Seen in {technique.sessionCount}{" "}
                {technique.sessionCount === 1 ? "session" : "sessions"}
                {technique.lastSeen ? ` — last ${formatDateTime(technique.lastSeen)}` : ""}
              </SheetDescription>
            </SheetHeader>

            <div className="mt-5 space-y-5 px-4 pb-6">
              {technique.confidence !== undefined ? (
                <section>
                  <div className="mb-2 flex items-center gap-2">
                    <h3 className="text-xs font-semibold uppercase tracking-[0.08em] text-foreground/80">
                      Mapping confidence
                    </h3>
                    {/*
                      Badge what produced THIS mapping, never a fixed label. A
                      rule-backed mapping is deterministic and carries
                      confidence 1.0; calling it "AI INFERENCE" is exactly the
                      confusion between a recorded fact and a model's guess
                      that the provenance model exists to prevent -- and it is
                      the distinction this drawer is for.
                    */}
                    <ProvenanceBadge
                      kind={technique.observed ? "OBSERVED" : "AI INFERENCE"}
                      showIcon={false}
                    />
                  </div>
                  <ConfidenceBar value={technique.confidence} />
                </section>
              ) : null}

              {technique.aiExplanation ? (
                <section>
                  <div className="mb-2 flex items-center gap-2">
                    <h3 className="text-xs font-semibold uppercase tracking-[0.08em] text-foreground/80">
                      AI explanation
                    </h3>
                    <ProvenanceBadge kind="AI INFERENCE" showIcon={false} />
                  </div>
                  <p className="rounded-md border border-ai/25 bg-ai/[0.05] px-3 py-2.5 text-sm leading-relaxed text-foreground/90">
                    {technique.aiExplanation}
                  </p>
                </section>
              ) : null}

              <section>
                <div className="mb-2 flex items-center gap-2">
                  <h3 className="text-xs font-semibold uppercase tracking-[0.08em] text-foreground/80">
                    Evidence
                  </h3>
                  <ProvenanceBadge kind="OBSERVED" showIcon={false} />
                </div>
                <EvidenceList evidence={technique.evidence} />
              </section>

              {technique.relatedCommands.length > 0 ? (
                <section>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-[0.08em] text-foreground/80">
                    Related commands
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {technique.relatedCommands.map((command) => (
                      <code
                        key={command}
                        className="rounded border border-border bg-background/60 px-1.5 py-1 font-mono text-[11px] text-foreground/85"
                      >
                        {command}
                      </code>
                    ))}
                  </div>
                </section>
              ) : null}

              <a
                href={`https://attack.mitre.org/techniques/${technique.id.replace(".", "/")}/`}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.08em] text-primary hover:underline"
              >
                Open on attack.mitre.org
                <ExternalLink className="size-3" aria-hidden />
              </a>
            </div>
          </>
        ) : (
          <EmptyState
            title="No technique selected"
            description="Select a technique from the matrix to inspect its evidence."
          />
        )}
      </SheetContent>
    </Sheet>
  );
}
