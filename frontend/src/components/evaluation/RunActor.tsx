/**
 * Who started an evaluation run.
 *
 * The backend stores three distinct values and this renders them as three
 * distinct things, because collapsing them is what an audit trail must not
 * do: "nobody was authenticated" and "we never recorded it" are different
 * facts, and showing both as a dash would let a gap in the history read as
 * an anonymous action.
 */
export function RunActor({
  startedBy,
  startedByLabel,
}: {
  startedBy: string;
  startedByLabel: string | null;
}) {
  if (startedBy === "unrecorded") {
    return (
      <span
        className="font-mono text-[11px] text-muted-foreground"
        title="This run predates the audit trail, so no actor was ever recorded — not the same as an anonymous run."
      >
        not recorded
      </span>
    );
  }

  if (startedBy === "unauthenticated") {
    return (
      <span
        className="font-mono text-[11px] text-warning"
        title="Authentication was disabled when this ran, so there was no identity to record."
      >
        unauthenticated
      </span>
    );
  }

  // `user:<clerk_id>`. The id is the identity and is always shown when there
  // is no label; the email is only a label, so it never replaces the id in
  // the tooltip.
  const id = startedBy.startsWith("user:") ? startedBy.slice(5) : startedBy;
  return (
    <span className="font-mono text-[11px] text-foreground" title={`Clerk user ${id}`}>
      {startedByLabel ?? id}
    </span>
  );
}
