import { Link, useRouterState } from "@tanstack/react-router";
import { Hexagon, X } from "lucide-react";
import { NAV_ITEMS } from "./navigation";
import { SystemStatusPanel } from "./SystemStatusPanel";
import { DemoDataBadge } from "@/components/common";
import { Button } from "@/components/ui/button";
import { isDemoMode } from "@/services";
import { cn } from "@/lib/utils";

function isActive(pathname: string, to: string): boolean {
  if (to === "/") return pathname === "/";
  return pathname === to || pathname.startsWith(`${to}/`);
}

export function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });

  return (
    <div className="flex h-full flex-col bg-sidebar">
      <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-sidebar-border px-4">
        <span className="flex size-7 items-center justify-center rounded-md border border-primary/40 bg-primary/12">
          <Hexagon className="size-4 text-primary" aria-hidden />
        </span>
        <div className="min-w-0 leading-tight">
          <p className="font-mono text-[13px] font-semibold tracking-[0.14em] text-sidebar-foreground">
            HONEYPOT AI
          </p>
          <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">
            Threat intelligence
          </p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Primary">
        <ul className="space-y-0.5">
          {NAV_ITEMS.map((item) => {
            const active = isActive(pathname, item.to);
            return (
              <li key={item.to}>
                <Link
                  to={item.to}
                  onClick={onNavigate}
                  title={item.hint}
                  className={cn(
                    "group relative flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors",
                    active
                      ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
                      : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
                  )}
                >
                  <span
                    className={cn(
                      "absolute inset-y-1.5 left-0 w-[2px] rounded-full bg-primary transition-opacity",
                      active ? "opacity-100" : "opacity-0",
                    )}
                    aria-hidden
                  />
                  <item.icon
                    className={cn("size-4 shrink-0", active && "text-primary")}
                    aria-hidden
                  />
                  <span className="truncate">{item.label}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="shrink-0 border-t border-sidebar-border p-3">
        {isDemoMode ? (
          <div className="mb-3 rounded-md border border-border bg-muted/30 p-2.5">
            <DemoDataBadge />
            <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground">
              Serving the synthetic dataset. Set{" "}
              <span className="font-mono">VITE_API_BASE_URL</span> to switch to FastAPI.
            </p>
          </div>
        ) : null}
        <SystemStatusPanel />
      </div>
    </div>
  );
}

export function DesktopSidebar() {
  return (
    <aside className="hidden w-60 shrink-0 border-r border-sidebar-border lg:block">
      <div className="sticky top-0 h-screen">
        <SidebarContent />
      </div>
    </aside>
  );
}

export function MobileSidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 lg:hidden">
      <button
        type="button"
        aria-label="Close navigation"
        onClick={onClose}
        className="absolute inset-0 bg-background/80 backdrop-blur-sm"
      />
      <div className="absolute inset-y-0 left-0 w-64 border-r border-sidebar-border shadow-xl">
        <Button
          variant="ghost"
          size="icon"
          onClick={onClose}
          className="absolute right-2 top-2.5 z-10 size-8"
          aria-label="Close navigation"
        >
          <X className="size-4" />
        </Button>
        <SidebarContent onNavigate={onClose} />
      </div>
    </div>
  );
}
