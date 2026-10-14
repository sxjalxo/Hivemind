import { Ban, ChevronRight } from "lucide-react";
import { Mono } from "@/components/common";
import type { RejectedClaim } from "@/types";

const REASON: Record<string, string> = {
  unknown_technique: "Named a technique outside the pinned ATT&CK catalog",
  citations_not_offered: "Cited events the model was never shown",
  citations_unresolved: "None of its cited events exist in this session",
};

const KIND: Record<string, string> = {
  technique_mapping: "Technique",
  observed_behavior: "Behaviour",
  suspicious_indicator: "Indicator",
};

/**
 * Claims the model made that a gate refused, and why. None of them is a
 * finding: they are listed so the refusal can be checked, not so their content
 * can be used. Renders nothing when nothing was refused.
 */
export function RejectedClaims({
  count,
  rejections,
}: {
  count: number;
  rejections: RejectedClaim[];
}) {
  if (count === 0) return null;
  const unexplained = count - rejections.length;

  return (
    <details className="group rounded-md border border-border bg-background/40">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:bg-accent/25">
        <Ban className="size-3.5" aria-hidden />
        <span className="font-semibold uppercase tracking-[0.08em]">
          {count} {count === 1 ? "claim" : "claims"} refused
        </span>
        <span className="hidden sm:inline">
          — not findings; shown so the refusal can be checked
        </span>
        <ChevronRight
          className="ml-auto size-3.5 transition-transform group-open:rotate-90"
          aria-hidden
        />
      </summary>
      <ul className="space-y-2 border-t border-border px-3 py-2.5">
        {rejections.map((r, i) => (
          <li key={i} className="text-xs">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
              <span className="font-medium text-foreground/90">{REASON[r.reason] ?? r.reason}</span>
              <span className="text-muted-foreground">
                {KIND[r.kind] ?? r.kind}
                {r.techniqueId ? ` ${r.techniqueId}` : ""}
              </span>
            </div>
            {r.text ? (
              <p className="mt-0.5 break-words text-muted-foreground">
                The model said: &ldquo;{r.text}&rdquo;
              </p>
            ) : null}
            {r.citedEventIds.length > 0 ? (
              <p className="mt-0.5 text-muted-foreground">
                Cited:{" "}
                {r.citedEventIds.map((id) => (
                  <Mono key={id} className="mr-1.5 text-[11px]">
                    {id}
                  </Mono>
                ))}
              </p>
            ) : null}
          </li>
        ))}
        {unexplained > 0 ? (
          <li className="text-xs text-muted-foreground">
            {unexplained} refused before reasons were recorded (analyses from before 14 October 2026
            kept only the count).
          </li>
        ) : null}
      </ul>
    </details>
  );
}
