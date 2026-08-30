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
const SIMILARITY_UNAVAILABLE: Record<string, string> = {
  command_cardinality_limit:
    "This attacker recorded more distinct commands than the similarity analysis compares in one pass, so any score would be computed from part of the evidence.",
  attacker_cardinality_limit:
    "More attackers were recorded than the similarity analysis compares in one pass, so a closer neighbour may not have been considered.",
};

export function SimilarityList({
  entries,
  complete,
  reason,
  onSelect,
}: {
  entries: { ip: string; score: number }[];
  // Required, not defaulted: defaulting to `true` would let a call site that
  // forgets them render an unavailable comparison as "no neighbours found",
  // which is the false statement this component exists to prevent.
  complete: boolean;
  reason: string | null;
  onSelect?: (ip: string) => void;
}) {
  // An empty list and an unavailable comparison are different findings, and
  // the second one must never be rendered as the first.
  if (!complete) {
    return (
      <div className="space-y-1.5">
        <p className="text-xs font-medium text-foreground">Similarity unavailable</p>
        <p className="text-xs text-muted-foreground">
          {(reason && SIMILARITY_UNAVAILABLE[reason]) ??
            "The comparison could not be completed over the full command set."}
        </p>
      </div>
    );
  }

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
