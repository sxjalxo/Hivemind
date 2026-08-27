import { ChevronRight, Code2, Search, TerminalSquare } from "lucide-react";
import { useMemo, useState } from "react";
import { CopyButton, EmptyState, RiskBadge } from "@/components/common";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { formatTime } from "@/utils/format";
import { cn } from "@/lib/utils";
import type { HoneypotEvent } from "@/types";

/**
 * Terminal-style session log. Renders the recorded command and its captured
 * output verbatim; the raw Elasticsearch document stays one click away so an
 * analyst can always check what the UI is summarising.
 */
export function LogViewer({ events }: { events: HoneypotEvent[] }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const categories = useMemo(() => {
    const set = new Set(events.map((event) => event.event.category));
    return ["all", ...[...set].sort()];
  }, [events]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return events.filter((event) => {
      if (category !== "all" && event.event.category !== category) return false;
      if (!needle) return true;
      return [
        event.process?.commandLine,
        event.process?.output,
        event.event.action,
        event.user?.name,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [events, query, category]);

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const transcript = filtered
    .map((event) =>
      event.process?.commandLine
        ? `[${formatTime(event.timestamp)}] $ ${event.process.commandLine}${
            event.process.output ? `\n${event.process.output}` : ""
          }`
        : `[${formatTime(event.timestamp)}] ${event.event.action}`,
    )
    .join("\n\n");

  return (
    <div className="flex min-h-0 flex-col">
      <div className="flex flex-col gap-2 border-b border-border p-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search commands and output"
            className="h-8 pl-8 font-mono text-xs"
            aria-label="Search session log"
          />
        </div>
        <Select value={category} onValueChange={setCategory}>
          <SelectTrigger className="h-8 w-full text-xs sm:w-[150px]" aria-label="Event type filter">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {categories.map((option) => (
              <SelectItem key={option} value={option} className="text-xs">
                {option === "all" ? "All event types" : option}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <CopyButton value={transcript} label="Copy transcript" className="hidden sm:inline-flex" />
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={TerminalSquare}
          title="No honeypot events found for the selected time range."
          description="Adjust the search text or event-type filter."
        />
      ) : (
        <div className="min-h-0 flex-1 overflow-auto bg-background/60 p-3">
          <div className="min-w-[520px] space-y-2.5">
            {filtered.map((event) => {
              const isOpen = expanded.has(event.id);
              const command = event.process?.commandLine;

              return (
                <div key={event.id} className="group">
                  <div className="flex items-start gap-2">
                    <button
                      type="button"
                      onClick={() => toggle(event.id)}
                      aria-expanded={isOpen}
                      aria-label={isOpen ? "Collapse event" : "Expand event"}
                      className="mt-[3px] shrink-0 text-muted-foreground transition-colors hover:text-foreground"
                    >
                      <ChevronRight
                        className={cn("size-3.5 transition-transform", isOpen && "rotate-90")}
                      />
                    </button>

                    <span className="shrink-0 select-none font-mono text-xs text-muted-foreground">
                      [{formatTime(event.timestamp)}]
                    </span>

                    {command ? (
                      <>
                        <span className="shrink-0 select-none font-mono text-xs text-success">
                          $
                        </span>
                        <span className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-[13px] text-foreground">
                          {command}
                        </span>
                        <CopyButton
                          value={command}
                          label="Copy command"
                          className="shrink-0 opacity-0 group-hover:opacity-100 focus:opacity-100"
                        />
                      </>
                    ) : (
                      <span className="min-w-0 flex-1 font-mono text-[13px] text-info">
                        {event.event.action}
                      </span>
                    )}

                    <RiskBadge level={event.risk.level} className="shrink-0" />
                  </div>

                  {event.process?.output ? (
                    <pre className="ml-[26px] mt-1 overflow-x-auto whitespace-pre-wrap break-all border-l border-border/70 pl-3 font-mono text-[13px] leading-relaxed text-muted-foreground">
                      {event.process.output}
                    </pre>
                  ) : null}

                  {isOpen ? <RawEventJson event={event} /> : null}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function RawEventJson({ event }: { event: HoneypotEvent }) {
  const json = JSON.stringify(event.raw ?? event, null, 2);
  return (
    <div className="ml-[26px] mt-2 rounded-md border border-border bg-surface/70">
      <div className="flex items-center justify-between border-b border-border px-2.5 py-1.5">
        <span className="flex items-center gap-1.5">
          <Code2 className="size-3 text-muted-foreground" aria-hidden />
          <span className="label-caps">Raw event document</span>
        </span>
        <CopyButton value={json} label="Copy JSON" />
      </div>
      <pre className="max-h-72 overflow-auto p-2.5 font-mono text-[11px] leading-relaxed text-foreground/80">
        {json}
      </pre>
    </div>
  );
}
