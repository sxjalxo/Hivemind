import { useState, type ReactNode } from "react";
import { DesktopSidebar, MobileSidebar } from "./AppSidebar";
import { TopBar } from "./TopBar";
import { TimeRangeProvider } from "@/hooks/useTimeRange";
import { Toaster } from "@/components/ui/sonner";

/**
 * Persistent application shell: sidebar + top bar + routed content.
 * Every page renders inside this so navigation state is never lost.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const [navOpen, setNavOpen] = useState(false);

  return (
    <TimeRangeProvider>
      <div className="flex min-h-screen bg-background">
        <DesktopSidebar />
        <MobileSidebar open={navOpen} onClose={() => setNavOpen(false)} />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar onOpenNav={() => setNavOpen(true)} />
          <main className="min-w-0 flex-1 px-4 py-5 md:px-6 md:py-6">{children}</main>
        </div>
      </div>
      <Toaster position="bottom-right" />
    </TimeRangeProvider>
  );
}
