import { useQuery } from "@tanstack/react-query";
import { Bell, ChevronDown, LogOut, Menu, Settings, ShieldCheck, UserRound } from "lucide-react";
import { GlobalSearchTrigger } from "./GlobalSearch";
import { TimeRangeSelector } from "./TimeRangeSelector";
import { StatusDot } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { systemStatusQuery } from "@/services/honeypots";
import type { ServiceStatus } from "@/types";

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

export function TopBar({
  onOpenNav,
  alertCount = 6,
}: {
  onOpenNav: () => void;
  alertCount?: number;
}) {
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

        <Button
          variant="ghost"
          size="icon"
          className="relative size-8"
          aria-label={`Notifications: ${alertCount} critical alerts`}
        >
          <Bell className="size-4" />
          {alertCount > 0 ? (
            <span className="absolute -right-0.5 -top-0.5 flex size-4 items-center justify-center rounded-full bg-critical font-mono text-[9px] font-semibold text-critical-foreground">
              {alertCount > 9 ? "9+" : alertCount}
            </span>
          ) : null}
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className="flex items-center gap-2 rounded-md border border-border bg-surface px-2 py-1.5 text-left transition-colors hover:border-border-strong"
            >
              <span className="flex size-6 items-center justify-center rounded bg-primary/15">
                <ShieldCheck className="size-3.5 text-primary" aria-hidden />
              </span>
              <span className="hidden leading-tight sm:block">
                <span className="block text-xs font-medium text-foreground">Analyst</span>
                <span className="block font-mono text-[10px] text-muted-foreground">tier-2</span>
              </span>
              <ChevronDown className="size-3.5 text-muted-foreground" aria-hidden />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52">
            <DropdownMenuLabel className="font-normal">
              <p className="text-xs font-medium text-foreground">SOC Analyst</p>
              <p className="font-mono text-[11px] text-muted-foreground">Tier-2 investigator</p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-xs">
              <UserRound className="size-3.5" /> Profile
            </DropdownMenuItem>
            <DropdownMenuItem className="text-xs">
              <Settings className="size-3.5" /> Preferences
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-xs">
              <LogOut className="size-3.5" /> Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
