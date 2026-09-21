import { useAuth } from "@clerk/tanstack-react-start";
import { isDemoMode } from "@/services";

export type Role = "admin" | "viewer";

/**
 * The signed-in user's role, mirroring `app.auth.role_of` on the backend.
 *
 * Read from the `role` claim Clerk puts in the session token, which is fed
 * from `public_metadata.role` on the user (see the instance's
 * `session.claims` config). Anything that is not exactly `admin` reads as
 * `viewer`, the same floor the backend applies and for the same reason: a
 * claim that fails to propagate must cost access, never grant it.
 *
 * `isAdmin` means admin on SOMETHING, which is only the right question
 * for a control that is not attached to a honeypot yet. Anywhere one is
 * in scope, ask `isAdminFor(honeypotId)`.
 *
 * **This is presentation only.** It decides whether a control is offered,
 * not whether an action is allowed -- the backend answers 403 regardless of
 * what the UI renders, and that is the check that counts. Hiding a button a
 * viewer cannot use is courtesy; it is not the boundary.
 *
 * Demo mode has no Clerk and no backend to refuse anything, so it reports
 * `admin` rather than rendering a read-only shell of an app whose whole
 * purpose is to demonstrate the features.
 */
export function useRole(): {
  role: Role;
  /** Admin on SOMETHING. Use `isAdminFor` before offering an action. */
  isAdmin: boolean;
  /** The caller's role on one honeypot, mirroring `auth.role_for`. */
  roleFor: (honeypotId: string) => Role;
  isAdminFor: (honeypotId: string) => boolean;
  isLoaded: boolean;
} {
  const { isLoaded, sessionClaims } = useAuth();

  const claims = sessionClaims as
    { role?: unknown; roles?: Record<string, unknown> } | null | undefined;

  const globalRole: Role = claims?.role === "admin" ? "admin" : "viewer";
  const perHoneypot = claims?.roles;

  // Mirrors `app.auth.role_for`: an explicit entry wins even when it is
  // LOWER than the global role, otherwise the map could only ever widen
  // access and would not be an access-control list.
  const roleFor = (honeypotId: string): Role => {
    if (isDemoMode) return "admin";
    const explicit =
      perHoneypot && typeof perHoneypot === "object" ? perHoneypot[honeypotId] : undefined;
    if (explicit === "admin") return "admin";
    if (explicit === "viewer") return "viewer";
    return globalRole;
  };

  if (isDemoMode) {
    return {
      role: "admin",
      isAdmin: true,
      roleFor,
      isAdminFor: () => true,
      isLoaded: true,
    };
  }

  const anyAdmin =
    globalRole === "admin" ||
    (perHoneypot != null &&
      typeof perHoneypot === "object" &&
      Object.values(perHoneypot).some((value) => value === "admin"));

  return {
    role: globalRole,
    isAdmin: anyAdmin,
    roleFor,
    isAdminFor: (honeypotId: string) => roleFor(honeypotId) === "admin",
    isLoaded,
  };
}
