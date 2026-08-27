import { Link } from "@tanstack/react-router";
import { CopyButton } from "@/components/common";
import { formatTime } from "@/utils/format";
import { cn } from "@/lib/utils";
import type { EvidenceRef } from "@/types";

/**
 * Every AI conclusion in this product must be traceable to raw telemetry.
 * This renders that trail: the exact artefact, the session it came from and
 * when it was recorded.
 */
export function EvidenceList({
  evidence,
  className,
  dense = false,
}: {
  evidence: EvidenceRef[];
  className?: string;
  dense?: boolean;
}) {
  if (evidence.length === 0) {
    return (
      <p className={cn("text-xs italic text-muted-foreground", className)}>
        No supporting evidence was attached to this conclusion.
      </p>
    );
  }

  return (
    <ul className={cn("space-y-1", className)}>
      {evidence.map((item, index) => (
        <li
          key={`${item.sessionId}-${item.artifact}-${index}`}
          className={cn(
            "group flex items-start gap-2 rounded border border-border/70 bg-background/50 px-2 py-1.5",
            dense && "px-1.5 py-1",
          )}
        >
          <span className="mt-[3px] shrink-0 select-none font-mono text-[11px] text-success">
            $
          </span>
          <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-[12px] text-foreground/90">
            {item.artifact}
          </code>
          <span className="flex shrink-0 items-center gap-1.5">
            {item.timestamp ? (
              <span className="font-mono text-[10px] text-muted-foreground">
                {formatTime(item.timestamp)}
              </span>
            ) : null}
            <Link
              to="/sessions/$sessionId"
              params={{ sessionId: item.sessionId }}
              className="font-mono text-[10px] text-muted-foreground underline-offset-2 hover:text-primary hover:underline"
              title={`Open ${item.sessionId}`}
            >
              {item.sessionId}
            </Link>
            <CopyButton
              value={item.artifact}
              className="opacity-0 group-hover:opacity-100 focus:opacity-100"
            />
          </span>
        </li>
      ))}
    </ul>
  );
}
