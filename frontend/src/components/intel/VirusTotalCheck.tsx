import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { provider } from "@/services";
import type { Indicator, VirusTotalVerdict } from "@/types";

const SENDABLE = new Set(["hash", "url", "ip"]);

/**
 * On-demand VirusTotal verdict for one indicator: THIRD-PARTY data.
 *
 * Nothing is asked until the analyst clicks, because the free tier allows four
 * lookups a minute, and only hashes, URLs and public IPs are ever sent (the
 * backend enforces this too). The verdict is antivirus engines' opinion of the
 * indicator, rendered as such -- it changes nothing else on the page.
 */
export function VirusTotalCheck({ indicator }: { indicator: Indicator }) {
  const [asked, setAsked] = useState(false);
  const { data, isFetching, isError } = useQuery({
    queryKey: ["virustotal", indicator.id],
    queryFn: () => provider.getVirusTotalVerdict(indicator.id),
    enabled: asked,
    staleTime: 60 * 60 * 1000,
  });

  if (!SENDABLE.has(indicator.type)) {
    return (
      <span
        className="font-mono text-[10px] text-muted-foreground"
        title={`A ${indicator.type} indicator is never sent to a third party.`}
      >
        not sent
      </span>
    );
  }
  if (!asked) {
    return (
      <button
        type="button"
        onClick={() => setAsked(true)}
        title="Ask VirusTotal for its existing report. Nothing is submitted."
        className="font-mono text-[10px] uppercase tracking-[0.08em] text-primary hover:underline"
      >
        Check
      </button>
    );
  }
  if (isFetching)
    return <span className="font-mono text-[10px] text-muted-foreground">asking…</span>;
  if (isError || !data) {
    return <span className="font-mono text-[10px] text-critical">lookup failed</span>;
  }
  return <Verdict verdict={data} />;
}

function Verdict({ verdict }: { verdict: VirusTotalVerdict }) {
  const label =
    verdict.status === "ok"
      ? `${verdict.malicious ?? 0}/${verdict.engines ?? "?"} malicious`
      : verdict.status === "not_found"
        ? "no report"
        : verdict.status.replace("_", " ");
  const tone =
    verdict.status === "ok" && (verdict.malicious ?? 0) > 0
      ? "text-critical"
      : "text-muted-foreground";
  const text = (
    <span
      className={`font-mono text-[10px] ${tone}`}
      title={verdict.detail ?? "VirusTotal (third party)"}
    >
      {label}
    </span>
  );
  return verdict.permalink ? (
    <a
      href={verdict.permalink}
      target="_blank"
      rel="noopener noreferrer"
      className="underline-offset-2 hover:underline"
      title="Open the report on VirusTotal (third party)"
    >
      {text}
    </a>
  ) : (
    text
  );
}
