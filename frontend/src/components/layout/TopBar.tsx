import { Show, SignInButton, SignUpButton, UserButton } from "@clerk/tanstack-react-start";
import { useQuery } from "@tanstack/react-query";
import { Menu } from "lucide-react";
import { GlobalSearchTrigger } from "./GlobalSearch";
import { TimeRangeSelector } from "./TimeRangeSelector";
import { StatusDot } from "@/components/common";
import { Button } from "@/components/ui/button";
import type { ServiceStatus } from "@/types";
import { systemStatusQuery } from "@/services/queries";

const UNKNOWN_AI: ServiceStatus = {
  id: "ai",
  name: "AI Engine",
  state: "unknown",
  detail: "Unknown",
};

/** Compact AI engine indicator, mirrored from the same status source as the sidebar. */
function AiEngineIndicator() {
  const { data, isPending } = useQuery(systemStatusQuery());
  const ai = data?.find((item) => item.id === "ai" || item.id === "ollama") ?? UNKNOWN_AI;

  return (
    <div
      className="hidden items-center gap-2 rounded-md border border-border bg-surface px-2.5 py-1.5 lg:flex"
      title={`AI engine: ${ai.detail ?? ai.state}`}
    >
      <StatusDot state={isPending ? "unknown" : ai.state} />
      <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
        AI Engine
      </span>
      <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-foreground">
        {isPending ? "..." : (ai.detail ?? ai.state)}
      </span>
    </div>
  );
}

/**
 * There is deliberately no notifications bell here.
 *
 * The original UI build shipped one whose badge read a hardcoded `alertCount =
 * 6` — no caller ever passed the prop — above a button that did nothing. It sat
 * in the top-right of every screen asserting six critical alerts that no
 * telemetry supported, which is the one thing this project claims it never
 * does. Same reasoning that retired the mock account menu below.
 *
 * Re-add it only with a real notables feed behind it.
 */
export function TopBar({ onOpenNav }: { onOpenNav: () => void }) {
  return (
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background/95 px-3 backdrop-blur supports-[backdrop-filter]:bg-background/80 md:px-5">
      <Button
        variant="ghost"
        size="icon"
        className="size-8 lg:hidden"
        onClick={onOpenNav}
        aria-label="Open navigation"
      >
        <Menu className="size-4" />
      </Button>

      <GlobalSearchTrigger className="min-w-0 flex-1 sm:max-w-md" />

      <div className="ml-auto flex shrink-0 items-center gap-2">
        <TimeRangeSelector className="hidden sm:flex" />
        <AiEngineIndicator />
        <AccountControls />
      </div>
    </header>
  );
}

/**
 * Real account controls, replacing the mock "SOC Analyst / tier-2" dropdown
 * that shipped with the original UI build.
 *
 * That menu looked like authentication and was not: its Profile, Preferences
 * and Sign out items did nothing, and the identity was a hardcoded string.
 * Leaving it beside a working sign-in would have given the app two user
 * menus, one of them lying.
 *
 * `Show` is this SDK's gate; the older `SignedIn`/`SignedOut` pair is not
 * exported by `@clerk/react` at this version.
 */
function AccountControls() {
  return (
    <>
      <Show when="signed-out">
        <SignInButton mode="modal">
          <Button variant="ghost" size="sm" className="h-8 text-xs">
            Sign in
          </Button>
        </SignInButton>
        <SignUpButton mode="modal">
          <Button size="sm" className="h-8 text-xs">
            Sign up
          </Button>
        </SignUpButton>
      </Show>
      <Show when="signed-in">
        <UserButton
          appearance={{
            elements: {
              // Match the 32px control height the rest of this bar uses, so
              // the avatar does not sit taller than the buttons beside it.
              userButtonAvatarBox: "size-7",
            },
          }}
        />
      </Show>
    </>
  );
}
