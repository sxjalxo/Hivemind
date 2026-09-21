import { useQuery } from "@tanstack/react-query";
import { useRole } from "./useRole";
import { sessionQueries } from "@/services/queries";

/**
 * Whether an action is offered, and why not when it is not.
 *
 * `disabled` and `title` are meant to be spread straight onto a button, so
 * the four controls this gates say the same thing the same way. They had
 * drifted: two named the honeypot, one said "this honeypot", and one omitted
 * it, which is the sort of difference nobody notices until a viewer is
 * confused by it.
 */
export interface AdminGate {
  allowed: boolean;
  disabled: boolean;
  title: string | undefined;
}

function gate(allowed: boolean, honeypotId: string | undefined): AdminGate {
  if (allowed) return { allowed: true, disabled: false, title: undefined };
  return {
    allowed: false,
    disabled: true,
    title: honeypotId ? `Requires the admin role on ${honeypotId}` : "Requires the admin role",
  };
}

/**
 * Gate an action on a honeypot the caller already knows.
 *
 * Presentation only. The backend answers 403 regardless of what was
 * rendered, and that is the check that counts -- see `useRole`.
 */
export function useAdminForHoneypot(honeypotId: string | undefined): AdminGate {
  const { isAdminFor } = useRole();
  if (!honeypotId) return gate(false, undefined);
  return gate(isAdminFor(honeypotId), honeypotId);
}

/**
 * Gate an action on the honeypot a SESSION belongs to.
 *
 * Roles are per honeypot and a session names one, so the two screens that
 * act on a selected session have to resolve it first. Both did, with the
 * same `.find()` written out twice; a lookup duplicated is a lookup that
 * gets fixed in one place.
 *
 * Reads the sessions list rather than fetching the session: both callers
 * already render that list to choose from, and react-query serves the same
 * cache entry, so this costs no extra request.
 */
export function useAdminForSession(sessionId: string | undefined): AdminGate {
  const { isAdminFor } = useRole();
  const sessions = useQuery(sessionQueries.list());

  const honeypotId = sessionId
    ? sessions.data?.find((session) => session.id === sessionId)?.honeypotId
    : undefined;

  // Unknown session -- still loading, or an id that is not in the list --
  // is refused rather than allowed. The backend would refuse it too, and
  // offering a button that is about to fail is worse than offering none.
  if (!honeypotId) return gate(false, undefined);
  return gate(isAdminFor(honeypotId), honeypotId);
}
