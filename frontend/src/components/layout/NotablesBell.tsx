import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Bell } from "lucide-react";
import { useState } from "react";
import { EmptyState, InlineNotice, ProvenanceBadge } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import { notablesQuery } from "@/services/queries";
import { formatDateTime } from "@/utils/format";
import type { Notable } from "@/types";

// Per-browser "seen up to" mark. Read state is a viewer convenience, so it lives
// here rather than on the server -- which, with authentication off, has no user
// to attach it to. Storage can be unavailable (private windows, blocked site
// data); the bell then simply counts everything in the window as unread.
const SEEN_KEY = "hivemind.notables.seenThrough";

function readSeen(): number {
  try {
    return Number(window.localStorage.getItem(SEEN_KEY)) || 0;
  } catch {
    return 0;
  }
}

function writeSeen(value: number) {
  try {
    window.localStorage.setItem(SEEN_KEY, String(value));
  } catch {
    // Not persisting the mark is acceptable; failing the click is not.
  }
}

/**
 * The notifications bell, back with a real feed behind it.
 *
 * The badge counts notables newer than this browser last opened the drawer.
 * Every item is derived by the backend from stored records and carries its own
 * provenance -- a model-rated risk is labelled AI INFERENCE here exactly as it
 * is on the session page. Nothing on this badge is a number the telemetry
 * does not support, which is the only reason it is allowed back.
 */
export function NotablesBell() {
  const { data, isError } = useQuery(notablesQuery());
  const [open, setOpen] = useState(false);
  const [seenThrough, setSeenThrough] = useState(readSeen);

  const unread = (data ?? []).filter((n) => Date.parse(n.timestamp) > seenThrough).length;

  const onOpenChange = (next: boolean) => {
    setOpen(next);
    if (next && data && data.length > 0) {
      const newest = Math.max(...data.map((n) => Date.parse(n.timestamp)));
      setSeenThrough(newest);
      writeSeen(newest);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <Button
        variant="ghost"
        size="icon"
        className="relative size-8"
        onClick={() => onOpenChange(true)}
        aria-label={
          isError
            ? "Notables unavailable"
            : unread > 0
              ? `${unread} new ${unread === 1 ? "notable" : "notables"}`
              : "Notables, none new"
        }
        title={isError ? "Notables could not be read" : undefined}
      >
        <Bell className={cn("size-4", isError && "text-muted-foreground")} />
        {unread > 0 ? (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-1 font-mono text-[9px] font-semibold text-primary-foreground">
            {unread > 9 ? "9+" : unread}
          </span>
        ) : null}
      </Button>
      <SheetContent className="w-full overflow-y-auto sm:max-w-md">
        <SheetHeader className="space-y-1 text-left">
          <SheetTitle className="text-base">Notables</SheetTitle>
          <SheetDescription className="text-xs">
            The last 7 days, derived from stored analyses, rule matches and campaigns. Each item is
            labelled with what kind of claim it is.
          </SheetDescription>
        </SheetHeader>
        <div className="mt-4 px-4 pb-6">
          {isError ? (
            <InlineNotice tone="critical">
              The notables feed could not be read. Nothing here means it failed, not that nothing
              happened.
            </InlineNotice>
          ) : !data ? null : data.length === 0 ? (
            <EmptyState
              icon={Bell}
              title="Nothing notable in the last 7 days."
              description="High-risk analyses, first rule-backed technique sightings and repeated campaigns appear here."
            />
          ) : (
            <ul className="space-y-2">
              {data.map((notable) => (
                <NotableItem key={notable.id} notable={notable} onNavigate={() => setOpen(false)} />
              ))}
            </ul>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

function NotableItem({ notable, onNavigate }: { notable: Notable; onNavigate: () => void }) {
  const body = (
    <>
      <div className="flex items-center justify-between gap-2">
        <ProvenanceBadge kind={notable.provenance} />
        <span className="font-mono text-[10px] text-muted-foreground">
          {formatDateTime(notable.timestamp)}
        </span>
      </div>
      <p className="mt-1.5 text-sm font-medium text-foreground">{notable.title}</p>
      <p className="mt-0.5 text-xs text-muted-foreground">{notable.detail}</p>
    </>
  );
  const className =
    "block rounded-md border border-border bg-background/40 p-3 transition-colors hover:bg-accent/30";
  return (
    <li>
      {notable.sessionId ? (
        <Link
          to="/sessions/$sessionId"
          params={{ sessionId: notable.sessionId }}
          onClick={onNavigate}
          className={className}
        >
          {body}
        </Link>
      ) : (
        <Link to="/sessions" onClick={onNavigate} className={className}>
          {body}
        </Link>
      )}
    </li>
  );
}
