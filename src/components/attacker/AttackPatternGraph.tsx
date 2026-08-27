import { ArrowDown, ArrowRight } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Ordered attack-pattern chain, e.g.
 * SSH Brute Force -> System Discovery -> Credential Discovery -> Payload Download -> Execution.
 *
 * Flows top-to-bottom on narrow viewports and left-to-right from `md` up.
 */
export function AttackPatternGraph({
  stages,
  className,
}: {
  stages: string[];
  className?: string;
}) {
  if (stages.length === 0) {
    return (
      <p className={cn("text-xs text-muted-foreground", className)}>
        No repeatable attack pattern has been derived for this attacker yet.
      </p>
    );
  }

  return (
    <ol
      className={cn(
        "flex flex-col items-stretch gap-0 md:flex-row md:items-center md:gap-0",
        className,
      )}
    >
      {stages.map((stage, index) => (
        <li key={`${stage}-${index}`} className="flex flex-col items-center md:flex-row">
          <div className="w-full rounded-md border border-border bg-surface/60 px-3 py-2 text-center md:w-auto md:min-w-[132px]">
            <span className="block font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">
              Step {index + 1}
            </span>
            <span className="mt-0.5 block text-xs leading-tight text-foreground/90">{stage}</span>
          </div>
          {index < stages.length - 1 ? (
            <>
              <ArrowDown
                className="my-1 size-3.5 shrink-0 text-muted-foreground md:hidden"
                aria-hidden
              />
              <ArrowRight
                className="mx-2 hidden size-3.5 shrink-0 text-muted-foreground md:block"
                aria-hidden
              />
            </>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

/** Behavioural similarity to other known attackers, 0-1 scored. */
export function SimilarityList({
  entries,
  onSelect,
}: {
  entries: { ip: string; score: number }[];
  onSelect?: (ip: string) => void;
}) {
  if (entries.length === 0) {
    return <p className="text-xs text-muted-foreground">No behavioural neighbours found.</p>;
  }

  return (
    <ul className="space-y-2">
      {entries.map((entry) => (
        <li key={entry.ip}>
          <button
            type="button"
            onClick={() => onSelect?.(entry.ip)}
            disabled={!onSelect}
            className="group block w-full text-left"
          >
            <span className="flex items-baseline justify-between gap-2 pb-1">
              <span className="font-mono text-[13px] text-foreground group-hover:text-primary">
                {entry.ip}
              </span>
              <span className="font-mono text-xs tabular-nums text-muted-foreground">
                {Math.round(entry.score * 100)}%
              </span>
            </span>
            <span className="block h-1 overflow-hidden rounded-full bg-muted">
              <span
                className="block h-full rounded-full bg-info"
                style={{ width: `${Math.round(entry.score * 100)}%` }}
              />
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}
