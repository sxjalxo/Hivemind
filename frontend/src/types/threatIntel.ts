export type IndicatorType = "ip" | "domain" | "url" | "hash" | "username" | "filename" | "command";

export interface Indicator {
  id: string;
  type: IndicatorType;
  value: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  sessionIds: string[];
  source: "OBSERVED" | "CORRELATED" | "STATIC ANALYSIS" | "AI INFERENCE";
  tags: string[];
}

export interface ThreatIntelSummary {
  indicators: Indicator[];
  countsByType: Record<IndicatorType, number>;
}

export type IocExportFormat = "stix" | "misp" | "blocklist";

/**
 * An export as a file to save, plus what was left out. Only public IPs, URLs and
 * hashes are exported; `excluded` counts the rest by reason, so the UI can say
 * how much of the list the file actually holds.
 */
export interface IocExport {
  format: IocExportFormat;
  filename: string;
  mediaType: string;
  content: string;
  exported: number;
  excluded: Record<string, number>;
}

/**
 * AbuseIPDB's view of an address: what OTHER people reported, not what this
 * honeypot saw. Every outcome is a status -- "not configured" and "rate limited"
 * are answers about the lookup, not errors.
 */
export interface Reputation {
  source: string;
  status:
    | "ok"
    | "not_configured"
    | "not_public"
    | "invalid_ip"
    | "rejected"
    | "rate_limited"
    | "unavailable";
  detail?: string | null;
  /** 0-100, AbuseIPDB's confidence the address is abusive. Their number, not ours. */
  abuseConfidence?: number | null;
  totalReports?: number | null;
  distinctReporters?: number | null;
  lastReportedAt?: string | null;
  countryCode?: string | null;
  isp?: string | null;
  usageType?: string | null;
  domain?: string | null;
  isTor?: boolean | null;
  checkedAt?: string | null;
}

/** VirusTotal's existing report for one indicator: THIRD-PARTY, read-only. */
export interface VirusTotalVerdict {
  source: string;
  status:
    | "ok"
    | "not_found"
    | "not_configured"
    | "not_supported"
    | "not_public"
    | "rejected"
    | "rate_limited"
    | "unavailable";
  detail?: string | null;
  malicious?: number | null;
  suspicious?: number | null;
  harmless?: number | null;
  undetected?: number | null;
  engines?: number | null;
  reputation?: number | null;
  lastAnalysisAt?: string | null;
  permalink?: string | null;
  checkedAt?: string | null;
}
