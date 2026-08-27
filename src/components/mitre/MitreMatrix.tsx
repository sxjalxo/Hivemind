import { MITRE_TACTICS, type MitreTechnique } from "@/types";
import { cn } from "@/lib/utils";
import { formatPct } from "@/utils/format";

/**
 * ATT&CK Enterprise-style matrix: one column per tactic, techniques stacked
 * beneath. Observed techniques are filled; the rest stay outlined so coverage
 * and absence are equally readable.
 */
export function MitreMatrix({
  techniques,
  onSelect,
  highlightId,
}: {
  techniques: MitreTechnique[];
  onSelect: (technique: MitreTechnique) => void;
  highlightId?: string;
}) {
  const byTactic = new Map<string, MitreTechnique[]>();
  for (const tactic of MITRE_TACTICS) byTactic.set(tactic, []);
  for (const technique of techniques) {
    byTactic.get(technique.tactic)?.push(technique);
  }

  return (
    <div className="overflow-x-auto pb-2">
      <div className="flex min-w-max gap-2">
        {MITRE_TACTICS.map((tactic) => {
          const column = byTactic.get(tactic) ?? [];
          const observed = column.filter((item) => item.observed).length;

          return (
            <div key={tactic} className="flex w-[164px] shrink-0 flex-col">
              <div className="mb-1.5 border-b border-border pb-1.5">
                <p className="text-[11px] font-semibold leading-tight text-foreground/85">
                  {tactic}
                </p>
                <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                  {observed}/{column.length} observed
                </p>
              </div>

              <div className="space-y-1">
                {column.length === 0 ? (
                  <p className="rounded border border-dashed border-border/70 px-2 py-2 text-center font-mono text-[10px] text-muted-foreground">
                    None
                  </p>
                ) : (
                  column.map((technique) => (
                    <button
                      key={technique.id}
                      type="button"
                      onClick={() => onSelect(technique)}
                      title={`${technique.id} — ${technique.name}`}
                      className={cn(
                        "w-full rounded border px-2 py-1.5 text-left transition-colors",
                        technique.observed
                          ? "border-primary/45 bg-primary/12 hover:border-primary hover:bg-primary/20"
                          : "border-border bg-surface/40 hover:border-border-strong hover:bg-accent/30",
                        highlightId === technique.id && "ring-1 ring-primary",
                      )}
                    >
                      <span
                        className={cn(
                          "block font-mono text-[10px] font-semibold",
                          technique.observed ? "text-primary" : "text-muted-foreground",
                        )}
                      >
                        {technique.id}
                      </span>
                      <span
                        className={cn(
                          "mt-0.5 block text-[11px] leading-tight",
                          technique.observed ? "text-foreground/90" : "text-muted-foreground",
                        )}
                      >
                        {technique.name}
                      </span>
                      {technique.observed ? (
                        <span className="mt-1 flex items-center justify-between font-mono text-[9px] text-muted-foreground">
                          <span>{technique.sessionCount} sess</span>
                          {technique.confidence !== undefined ? (
                            <span>{formatPct(technique.confidence)}</span>
                          ) : null}
                        </span>
                      ) : null}
                    </button>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function MatrixLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <span className="flex items-center gap-1.5">
        <span
          className="size-2.5 rounded-[2px] border border-primary/45 bg-primary/20"
          aria-hidden
        />
        <span className="text-xs text-muted-foreground">Observed in telemetry</span>
      </span>
      <span className="flex items-center gap-1.5">
        <span className="size-2.5 rounded-[2px] border border-border bg-surface" aria-hidden />
        <span className="text-xs text-muted-foreground">Not observed</span>
      </span>
    </div>
  );
}
