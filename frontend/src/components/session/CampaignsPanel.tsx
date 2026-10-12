import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { InlineNotice, Mono, Panel, ProvenanceBadge } from "@/components/common";
import { formatDateTime } from "@/utils/format";
import { sessionQueries } from "@/services/queries";
import type { Campaign } from "@/types";

const SHOWN_SESSIONS = 3;
const SHOWN_COMMANDS = 4;

/**
 * Sessions that replayed one script, grouped.
 *
 * Renders NOTHING while loading and when the answer is a complete "no
 * campaigns" -- that is the common case on a quiet honeypot and not worth a
 * panel. It does speak up when the grouping failed or covered only part of
 * the sessions, because silence there would read as "nothing repeats".
 */
export function CampaignsPanel() {
  const { data, isError } = useQuery(sessionQueries.campaigns());

  if (isError) {
    return (
      <InlineNotice tone="critical">
        Campaign grouping could not be read. Sessions below are unaffected.
      </InlineNotice>
    );
  }
  if (!data || (data.complete && data.campaigns.length === 0)) return null;

  return (
    <Panel
      title="Campaigns"
      description="Sessions that ran the identical command sequence, with IP addresses and hashes masked. Grouped deterministically, no model involved."
      actions={<ProvenanceBadge kind="CORRELATED" />}
      bodyClassName="p-0"
    >
      {!data.complete ? (
        <InlineNotice tone="warn" className="m-3">
          Grouped from the newest {data.sessionsConsidered} sessions only (
          {data.incompleteReason ?? "limit reached"}). Older sessions were not examined, so a
          campaign may be larger than shown.
        </InlineNotice>
      ) : null}
      {data.campaigns.length === 0 ? (
        <p className="px-4 py-3 text-xs text-muted-foreground">
          No repeated command sequence among the sessions examined.
        </p>
      ) : (
        <ul className="divide-y divide-border/60">
          {data.campaigns.map((campaign) => (
            <CampaignRow key={campaign.fingerprint} campaign={campaign} />
          ))}
        </ul>
      )}
    </Panel>
  );
}

function CampaignRow({ campaign }: { campaign: Campaign }) {
  const extraSessions = campaign.sessionCount - SHOWN_SESSIONS;
  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <Mono className="text-[13px]">{campaign.fingerprint}</Mono>
        <span className="text-xs text-foreground/85">
          {campaign.sessionCount} sessions · {campaign.attackerIpCount} source{" "}
          {campaign.attackerIpCount === 1 ? "IP" : "IPs"} · {campaign.honeypotIds.join(", ")}
        </span>
        <Mono tone="muted" className="ml-auto text-[11px]">
          {formatDateTime(campaign.firstSeen)} → {formatDateTime(campaign.lastSeen)}
        </Mono>
      </div>
      <p className="mt-1.5 truncate font-mono text-[11px] text-muted-foreground">
        {campaign.commands.slice(0, SHOWN_COMMANDS).join("  ;  ")}
        {campaign.commandCount > SHOWN_COMMANDS
          ? `  ; … ${campaign.commandCount - SHOWN_COMMANDS} more`
          : ""}
      </p>
      <div className="mt-1.5 flex flex-wrap items-center gap-2">
        {campaign.sessionIds.slice(0, SHOWN_SESSIONS).map((id) => (
          <Link
            key={id}
            to="/sessions/$sessionId"
            params={{ sessionId: id }}
            className="font-mono text-[11px] text-foreground/90 underline-offset-4 hover:text-primary hover:underline"
          >
            {id}
          </Link>
        ))}
        {extraSessions > 0 ? (
          <span className="font-mono text-[10px] text-muted-foreground">+{extraSessions}</span>
        ) : null}
      </div>
    </li>
  );
}
