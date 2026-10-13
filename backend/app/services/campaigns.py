"""Sessions that ran the same command sequence, grouped into campaigns.

A honeypot on the public internet sees one botnet script replayed from
hundreds of addresses. Read session by session, that is hundreds of rows that
each look new; grouped, it is one campaign with a size. The grouping is a
deterministic fingerprint -- no model involved -- so a campaign is an observed
fact about the telemetry, not an inference.

The fingerprint is the ORDERED sequence of normalised commands. Normalising
(`profiles.normalize_command`) replaces IP literals and hex digests, so one
dropper pointed at two different C2 hosts is still one campaign. Order is kept
because `wget; chmod; ./x` and `./x; chmod; wget` are different behaviour.
Sessions with no commands at all (pure credential spraying) are not grouped:
an empty sequence is identical across every such session and would merge
unrelated attackers into one meaningless "campaign".
"""

import hashlib
from collections import defaultdict

from sqlalchemy import select

from app.config import get_settings
from app.db.models import Analysis
from app.db.session import get_session_factory
from app.es.client import get_es
from app.models.session import Campaign, CampaignList, SessionTwins, TwinAnalysis
from app.services.profiles import normalize_command

_COMMAND_ACTION = "cowrie.command.input"

# Sessions examined, newest first.
_MAX_SESSIONS = 2000

# One search page (Elasticsearch's default `max_result_window`). Sessions are
# admitted newest-first only while their WHOLE command list still fits, so a
# session is never fingerprinted from part of its commands: a partial sequence
# would fingerprint differently from the same script run in full and quietly
# split one campaign in two.
_MAX_COMMAND_EVENTS = 10_000

# Per-campaign list caps for the response. Counts are always exact.
_LIST_CAP = 20


def fingerprint(commands: list[str]) -> str:
    """Stable id for an ordered command sequence. Empty input is not a campaign."""
    canonical = "\n".join(normalize_command(c) for c in commands)
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


async def _group_sessions(
    deny_honeypots: set[str] | None,
) -> tuple[dict[str, list[list[dict]]], int, str | None]:
    """Every examined session's ordered command events, grouped by fingerprint.

    Returns the groups, how many sessions were examined, and why examination
    stopped short (None when every session with commands was examined).
    """
    settings = get_settings()
    base: dict = {"filter": [{"term": {"event.action": _COMMAND_ACTION}}]}
    # Scoped in the query, as `list_sessions` is: a denied sensor's sessions
    # must not even consume the session budget below.
    if deny_honeypots:
        base["must_not"] = [{"terms": {"honeypot.id": sorted(deny_honeypots)}}]

    sessions_agg = (
        await get_es().search(
            index=settings.es_index,
            query={"bool": base},
            size=0,
            aggs={
                "sessions": {
                    "terms": {
                        "field": "session.id",
                        "size": _MAX_SESSIONS,
                        "order": {"first_seen": "desc"},
                    },
                    "aggs": {"first_seen": {"min": {"field": "@timestamp"}}},
                }
            },
        )
    )["aggregations"]["sessions"]

    chosen: list[str] = []
    budget = 0
    reason: str | None = None
    if sessions_agg.get("sum_other_doc_count", 0):
        reason = "session_limit"
    for bucket in sessions_agg["buckets"]:
        if budget + bucket["doc_count"] > _MAX_COMMAND_EVENTS:
            reason = "command_event_limit"
            break
        chosen.append(bucket["key"])
        budget += bucket["doc_count"]

    by_session: dict[str, list[dict]] = defaultdict(list)
    if chosen:
        hits = (
            await get_es().search(
                index=settings.es_index,
                query={
                    "bool": {**base, "filter": [*base["filter"], {"terms": {"session.id": chosen}}]}
                },
                sort=[{"@timestamp": "asc"}],
                size=budget,
                source=[
                    "@timestamp",
                    "session.id",
                    "source.ip",
                    "honeypot.id",
                    "process.command_line",
                ],
            )
        )["hits"]["hits"]
        for hit in hits:
            src = hit["_source"]
            by_session[src["session"]["id"]].append(src)

    groups: dict[str, list[list[dict]]] = defaultdict(list)
    for events in by_session.values():
        commands = [e.get("process", {}).get("command_line") or "" for e in events]
        groups[fingerprint(commands)].append(events)
    return groups, len(chosen), reason


async def list_campaigns(
    deny_honeypots: set[str] | None = None,
    min_sessions: int = 2,
    limit: int | None = None,
) -> CampaignList:
    groups, considered, reason = await _group_sessions(deny_honeypots)

    campaigns: list[Campaign] = []
    for fp, members in groups.items():
        if len(members) < min_sessions:
            continue
        # Newest session first, matching the session list.
        members.sort(key=lambda events: events[0]["@timestamp"], reverse=True)
        ips: list[str] = []
        honeypots: list[str] = []
        for events in members:
            ip = events[0].get("source", {}).get("ip")
            if ip and ip not in ips:
                ips.append(ip)
            hp = events[0].get("honeypot", {}).get("id")
            if hp and hp not in honeypots:
                honeypots.append(hp)
        sample = members[0]
        campaigns.append(
            Campaign(
                fingerprint=fp,
                commands=[
                    normalize_command(e.get("process", {}).get("command_line") or "")
                    for e in sample
                ][:_LIST_CAP],
                command_count=len(sample),
                session_count=len(members),
                session_ids=[events[0]["session"]["id"] for events in members][:_LIST_CAP],
                attacker_ips=ips[:_LIST_CAP],
                attacker_ip_count=len(ips),
                honeypot_ids=honeypots,
                first_seen=min(events[0]["@timestamp"] for events in members),
                last_seen=max(events[-1]["@timestamp"] for events in members),
            )
        )

    campaigns.sort(key=lambda c: (c.session_count, c.last_seen), reverse=True)
    if limit is not None:
        campaigns = campaigns[:limit]
    return CampaignList(
        campaigns=campaigns,
        sessions_considered=considered,
        complete=reason is None,
        incomplete_reason=reason,
    )


async def identical_sessions(
    session_id: str, deny_honeypots: set[str] | None = None
) -> SessionTwins:
    """Other sessions that ran this session's exact command sequence, and which of
    them already have an analysis.

    Deliberately a POINTER, never a copy. Reusing session A's analysis as session
    B's would make every claim on B cite A's log lines -- the one thing this
    system promises never happens. So the analyst is shown A's analysis, on A's
    page, with A's evidence; deciding it also describes B is theirs to make.
    """
    from app.services.session_builder import get_session_events  # circular at module level

    commands = [
        e.process.command_line
        for e in await get_session_events(session_id)
        if e.event.action == _COMMAND_ACTION and e.process and e.process.command_line
    ]
    if not commands:
        # No sequence, no twins: an empty sequence matches every login-only session.
        return SessionTwins(fingerprint=None, twin_count=0, analysed=[], complete=True)

    fp = fingerprint(commands)
    groups, _, reason = await _group_sessions(deny_honeypots)
    twins = [events[0]["session"]["id"] for events in groups.get(fp, [])]
    twins = [t for t in twins if t != session_id]

    analysed: list[TwinAnalysis] = []
    if twins:
        async with get_session_factory()() as db:
            rows = (
                (
                    await db.execute(
                        select(Analysis)
                        .where(Analysis.session_id.in_(twins), Analysis.status == "completed")
                        .order_by(Analysis.created_at.desc())
                    )
                )
                .scalars()
                .all()
            )
        seen: set[str] = set()
        for row in rows:  # newest first: keep each twin's latest
            if row.session_id in seen:
                continue
            seen.add(row.session_id)
            analysed.append(
                TwinAnalysis(
                    session_id=row.session_id,
                    analysis_id=str(row.id),
                    classification=row.classification,
                    risk=row.risk,
                    created_at=row.created_at.isoformat(),
                )
            )

    return SessionTwins(
        fingerprint=fp,
        twin_count=len(twins),
        analysed=analysed[:_LIST_CAP],
        complete=reason is None,
        incomplete_reason=reason,
    )
