import { cn } from "@/lib/utils";

/**
 * MITRE technique chip. `observed` distinguishes techniques backed by honeypot
 * evidence from techniques merely present in the matrix.
 */
export function MitreBadge({
  techniqueId,
  name,
  observed = true,
  onClick,
  className,
}: {
  techniqueId: string;
  name?: string;
  observed?: boolean;
  onClick?: () => void;
  className?: string;
}) {
  const Wrapper = onClick ? "button" : "span";
  return (
    <Wrapper
      {...(onClick ? { type: "button" as const, onClick } : {})}
      title={name ? `${techniqueId} — ${name}` : techniqueId}
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-1.5 py-[3px] font-mono text-[10px] font-semibold uppercase tracking-[0.06em] leading-none transition-colors",
        observed
          ? "border-primary/40 bg-primary/12 text-primary"
          : "border-border bg-muted/40 text-muted-foreground",
        onClick && "hover:border-primary hover:bg-primary/20",
        className,
      )}
    >
      {techniqueId}
      {name ? (
        <span className="max-w-[140px] truncate font-normal normal-case opacity-80">{name}</span>
      ) : null}
    </Wrapper>
  );
}

/** Compact tactic chain, e.g. Credential Access -> Discovery -> Execution. */
export function ClassificationChain({ chain, className }: { chain: string[]; className?: string }) {
  if (chain.length === 0) {
    return <span className="text-xs text-muted-foreground">Unclassified</span>;
  }
  return (
    <span className={cn("flex flex-wrap items-center gap-x-1 gap-y-1 text-xs", className)}>
      {chain.map((step, index) => (
        <span key={`${step}-${index}`} className="flex items-center gap-1">
          {index > 0 ? <span className="text-muted-foreground/60">&rarr;</span> : null}
          <span className="text-foreground/85">{step}</span>
        </span>
      ))}
    </span>
  );
}
