import { useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Bug,
  Grid3x3,
  ScrollText,
  Search,
  ShieldAlert,
  TerminalSquare,
  User,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { cn } from "@/lib/utils";
import { sessionQueries, threatIntelQueries } from "@/services/queries";

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const CVE = /^CVE-\d{4}-\d{4,7}$/i;
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/i;
const SESSION = /^(session|cowrie-session)[-\w]*$/i;
const COMMAND_HEAD = /^(wget|curl|chmod|cat|uname|whoami|ls|rm|crontab|sh|bash)\b/i;

export type QueryKind = "ip" | "cve" | "technique" | "session" | "username" | "command" | "text";

/** Classifies an analyst query so the palette can offer the right destination. */
export function classifyQuery(raw: string): QueryKind {
  const value = raw.trim();
  if (!value) return "text";
  if (IPV4.test(value)) return "ip";
  if (CVE.test(value)) return "cve";
  if (TECHNIQUE.test(value)) return "technique";
  if (SESSION.test(value)) return "session";
  if (/^(root|admin|ubuntu|pi|oracle|guest)$/i.test(value)) return "username";
  if (COMMAND_HEAD.test(value) || /\s/.test(value)) return "command";
  return "text";
}

const KIND_LABEL: Record<QueryKind, string> = {
  ip: "IP address",
  cve: "CVE identifier",
  technique: "ATT&CK technique",
  session: "Session identifier",
  username: "Username",
  command: "Command",
  text: "Free text",
};

export function GlobalSearchTrigger({ className }: { className?: string }) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={cn(
          "flex h-8 items-center gap-2 rounded-md border border-border bg-surface px-2.5 text-left text-xs text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground",
          className,
        )}
      >
        <Search className="size-3.5 shrink-0" aria-hidden />
        <span className="hidden truncate sm:inline">
          Search IPs, sessions, techniques, commands
        </span>
        <kbd className="ml-auto hidden shrink-0 rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] md:inline">
          Ctrl K
        </kbd>
      </button>
      <GlobalSearchDialog open={open} onOpenChange={setOpen} />
    </>
  );
}

function GlobalSearchDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [value, setValue] = useState("");
  const navigate = useNavigate();
  const trimmed = value.trim();
  const kind = useMemo(() => classifyQuery(trimmed), [trimmed]);

  const { data: sessions = [] } = useQuery({ ...sessionQueries.list(), enabled: open });
  const { data: indicators = [] } = useQuery({
    ...threatIntelQueries.indicators(),
    enabled: open,
  });

  const go = (to: string, search?: Record<string, string>) => {
    onOpenChange(false);
    setValue("");
    void navigate({ to, ...(search ? { search } : {}) } as never);
  };

  const lower = trimmed.toLowerCase();

  const matchedSessions = trimmed
    ? sessions
        .filter(
          (session) =>
            session.id.toLowerCase().includes(lower) ||
            session.attackerIp.includes(trimmed) ||
            session.mitreTechniqueIds.some((id) => id.toLowerCase() === lower),
        )
        .slice(0, 5)
    : sessions.slice(0, 4);

  const matchedIndicators = trimmed
    ? indicators.filter((ioc) => ioc.value.toLowerCase().includes(lower)).slice(0, 5)
    : [];

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandInput
        placeholder="192.168.1.45   T1059   wget   root   SESSION-8F42A1"
        value={value}
        onValueChange={setValue}
      />
      <CommandList>
        <CommandEmpty>No matching telemetry. Try an IP, technique ID or command.</CommandEmpty>

        {trimmed ? (
          <CommandGroup heading={`Interpreted as: ${KIND_LABEL[kind]}`}>
            <CommandItem value={`logs-${trimmed}`} onSelect={() => go("/logs", { q: trimmed })}>
              <ScrollText className="size-4 text-muted-foreground" />
              Search honeypot events for <span className="font-mono">{trimmed}</span>
            </CommandItem>
            {kind === "ip" ? (
              <CommandItem
                value={`attacker-${trimmed}`}
                onSelect={() => go(`/attackers/${encodeURIComponent(trimmed)}`)}
              >
                <User className="size-4 text-muted-foreground" />
                Open attacker profile <span className="font-mono">{trimmed}</span>
              </CommandItem>
            ) : null}
            {kind === "technique" ? (
              <CommandItem
                value={`mitre-${trimmed}`}
                onSelect={() => go("/mitre", { technique: trimmed.toUpperCase() })}
              >
                <Grid3x3 className="size-4 text-muted-foreground" />
                Open ATT&CK technique <span className="font-mono">{trimmed.toUpperCase()}</span>
              </CommandItem>
            ) : null}
            {kind === "cve" ? (
              <CommandItem
                value={`cve-${trimmed}`}
                onSelect={() => go("/threat-intel", { q: trimmed })}
              >
                <Bug className="size-4 text-muted-foreground" />
                Look up <span className="font-mono">{trimmed.toUpperCase()}</span> in threat
                intelligence
              </CommandItem>
            ) : null}
            {kind === "command" || kind === "username" ? (
              <CommandItem
                value={`ioc-${trimmed}`}
                onSelect={() => go("/threat-intel", { q: trimmed })}
              >
                <TerminalSquare className="size-4 text-muted-foreground" />
                Find indicators containing <span className="font-mono">{trimmed}</span>
              </CommandItem>
            ) : null}
          </CommandGroup>
        ) : null}

        {matchedSessions.length > 0 ? (
          <>
            <CommandSeparator />
            <CommandGroup heading="Attack sessions">
              {matchedSessions.map((session) => (
                <CommandItem
                  key={session.id}
                  value={`${session.id} ${session.attackerIp}`}
                  onSelect={() => go(`/sessions/${session.id}`)}
                >
                  <Activity className="size-4 text-muted-foreground" />
                  <span className="font-mono">{session.id}</span>
                  <span className="ml-auto font-mono text-[11px] text-muted-foreground">
                    {session.attackerIp}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        ) : null}

        {matchedIndicators.length > 0 ? (
          <>
            <CommandSeparator />
            <CommandGroup heading="Indicators">
              {matchedIndicators.map((ioc) => (
                <CommandItem
                  key={ioc.id}
                  value={ioc.value}
                  onSelect={() => go("/threat-intel", { q: ioc.value })}
                >
                  <ShieldAlert className="size-4 text-muted-foreground" />
                  <span className="truncate font-mono">{ioc.value}</span>
                  <span className="ml-auto font-mono text-[10px] uppercase text-muted-foreground">
                    {ioc.type}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        ) : null}
      </CommandList>
    </CommandDialog>
  );
}
