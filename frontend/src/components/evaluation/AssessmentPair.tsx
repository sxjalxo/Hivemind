import { ConfidenceBar } from "@/components/common";
import {
  CHARACTERISTIC_LABELS,
  EVALUATOR_ABSENCE_TEXT,
  NOT_ESTABLISHED,
} from "@/services/evaluation";
import { cn } from "@/lib/utils";
import type { EvaluationCategoryScore, EvaluatorStatus } from "@/types";

/**
 * The two assessments of one characteristic, side by side and NEVER combined.
 *
 * "Deterministic assessment" answers "did the honeypot do the checkable
 * things?"; "Evaluator assessment" answers "would an attacker believe it?".
 * They are different questions, so there is no average, no composite and no
 * overall score here or anywhere else.
 *
 * Both values are 0-1 on the wire and are rendered as percentages by
 * `ConfidenceBar`, the house convention for a 0-1 fraction. A null is NOT a
 * zero: it means nothing was established, and it renders as words.
 */
export function AssessmentPair({
  score,
  evaluatorStatus,
  className,
}: {
  score: EvaluationCategoryScore;
  /** Explains an absent evaluator rating in the evaluator's own terms. */
  evaluatorStatus: EvaluatorStatus;
  className?: string;
}) {
  const evaluatorAbsence =
    evaluatorStatus === "completed" ? null : EVALUATOR_ABSENCE_TEXT[evaluatorStatus];

  return (
    <div className={cn("rounded-lg border border-border bg-background/40 p-3.5", className)}>
      <h3 className="text-sm font-semibold tracking-tight text-foreground">
        {CHARACTERISTIC_LABELS[score.characteristic]}
      </h3>

      <div className="mt-3 grid gap-3 sm:grid-cols-2 sm:divide-x sm:divide-border">
        <div className="min-w-0 sm:pr-3">
          <Assessment
            label="Deterministic assessment"
            value={score.deterministicScore}
            question="Did the honeypot do the checkable things?"
            absence={NOT_ESTABLISHED}
            absenceHint="No checkable fact was established for this characteristic. That is a gap in what we could measure, not a score of zero."
          />
        </div>
        <div className="min-w-0 sm:pl-3">
          <Assessment
            label="Evaluator assessment"
            value={score.evaluatorRating}
            question="Would an attacker believe it?"
            absence={evaluatorAbsence ?? NOT_ESTABLISHED}
            absenceHint={
              evaluatorAbsence
                ? "The evaluator produced no rating for this run, so there is nothing to show. This is not a score of zero."
                : "The evaluator ran but established nothing for this characteristic. Not a score of zero."
            }
          />
        </div>
      </div>
    </div>
  );
}

function Assessment({
  label,
  value,
  question,
  absence,
  absenceHint,
}: {
  label: string;
  value: number | null;
  question: string;
  absence: string;
  absenceHint: string;
}) {
  return (
    <div className="min-w-0">
      {value === null ? (
        <>
          <p className="label-caps">{label}</p>
          <p
            title={absenceHint}
            className="mt-1.5 text-xs font-medium italic leading-relaxed text-muted-foreground"
          >
            {absence}
          </p>
        </>
      ) : (
        <ConfidenceBar value={value} label={label} />
      )}
      <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground/80">{question}</p>
    </div>
  );
}

/**
 * A compact score pair for table cells: percentage, or the words for a null.
 * Same rules, less room -- still never a zero for a null.
 */
export function ScorePill({
  value,
  absent = false,
  className,
}: {
  value: number | null;
  /** True when the characteristic is absent from the run entirely. */
  absent?: boolean;
  className?: string;
}) {
  if (absent) {
    return (
      <span
        title="This run did not measure this characteristic at all — an absent characteristic is not a null one."
        className={cn("font-mono text-[11px] italic text-muted-foreground/60", className)}
      >
        not measured
      </span>
    );
  }
  if (value === null) {
    return (
      <span
        title="Nothing was established for this characteristic. A gap in what we could measure, not a score of zero."
        className={cn("font-mono text-[11px] italic text-muted-foreground", className)}
      >
        {NOT_ESTABLISHED}
      </span>
    );
  }
  return (
    <span className={cn("font-mono text-[11px] font-semibold tabular-nums", className)}>
      {Math.round(Math.max(0, Math.min(1, value)) * 100)}%
    </span>
  );
}
