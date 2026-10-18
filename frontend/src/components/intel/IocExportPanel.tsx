import { Download } from "lucide-react";
import { useState } from "react";
import { InlineNotice, Panel } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { provider } from "@/services";
import { downloadText } from "@/utils/csv";
import type { IocExport, IocExportFormat } from "@/types";

const FORMATS: { value: IocExportFormat; label: string }[] = [
  { value: "stix", label: "STIX 2.1 bundle" },
  { value: "misp", label: "MISP event (JSON)" },
  { value: "blocklist", label: "IP blocklist (text)" },
];

// [singular, plural] per exclusion reason.
const REASONS: Record<string, [string, string]> = {
  "type:command": ["command", "commands"],
  "type:username": ["username", "usernames"],
  "type:url": ["URL", "URLs"],
  "type:hash": ["hash", "hashes"],
  "non-public-ip": ["private or local address", "private or local addresses"],
  "unparseable-ip": ["unreadable address", "unreadable addresses"],
  "unknown-hash-length": ["hash of unknown type", "hashes of unknown type"],
};

function excludedSummary(excluded: Record<string, number>): string {
  const parts = Object.entries(excluded).map(([reason, n]) => {
    const [one, many] = REASONS[reason] ?? [reason, reason];
    return `${n} ${n === 1 ? one : many}`;
  });
  return parts.length ? `Left out: ${parts.join(", ")}.` : "Nothing was left out.";
}

/**
 * Indicators for tools that act on them. Only public IPs, URLs and file hashes
 * go out -- a username or a command in someone's IDS matches every ordinary
 * login -- and the panel says what was left out, so a 3-line file is never
 * mistaken for the whole list.
 */
export function IocExportPanel() {
  const [format, setFormat] = useState<IocExportFormat>("stix");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<IocExport | null>(null);
  const [failed, setFailed] = useState(false);

  const run = async () => {
    setBusy(true);
    setFailed(false);
    try {
      const exported = await provider.exportIndicators(format);
      downloadText(exported.filename, exported.content, exported.mediaType);
      setResult(exported);
    } catch {
      setResult(null);
      setFailed(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title="Export for other tools"
      description="Public IP addresses, URLs and file hashes only. Each item keeps its provenance."
    >
      <div className="flex flex-col gap-2 sm:flex-row">
        <Select value={format} onValueChange={(v) => setFormat(v as IocExportFormat)}>
          <SelectTrigger className="h-9 text-xs sm:w-[220px]" aria-label="Export format">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {FORMATS.map((f) => (
              <SelectItem key={f.value} value={f.value} className="text-xs">
                {f.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button size="sm" className="h-9" disabled={busy} onClick={() => void run()}>
          <Download className="size-3.5" aria-hidden />
          {busy ? "Exporting..." : "Export"}
        </Button>
      </div>
      {failed ? (
        <InlineNotice tone="critical" className="mt-3">
          The export could not be built. No file was saved.
        </InlineNotice>
      ) : result ? (
        <p className="mt-3 text-xs text-muted-foreground">
          Saved <span className="font-mono">{result.filename}</span> with {result.exported}{" "}
          {result.exported === 1 ? "indicator" : "indicators"}. {excludedSummary(result.excluded)}
        </p>
      ) : null}
    </Panel>
  );
}
