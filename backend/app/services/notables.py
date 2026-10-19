"""What is worth an analyst's attention, derived on demand from what is stored.

There is no notables table and nothing is marked read here: every item is
recomputed from analyses, technique mappings and campaigns each time it is
asked for, so it cannot drift from them. Read state is the viewer's, kept in
their browser.

Each kind carries the provenance of the claim it rests on, because they are
three different kinds of claim:

* `high_risk_session` -- the MODEL rated a session high or critical. The risk
  is not evidence-gated (see `compaction.build_prompt`) and moves between runs,
  so this is `AI INFERENCE`, never presented as a measurement.
* `technique_first_seen` -- a RULE matched a technique that no earlier
  rule-backed mapping had. Deterministic, so `OBSERVED`. Model-proposed
  mappings are deliberately not notable: a first sighting is a claim about the
  telemetry, and an inference is not one.
* `campaign` -- one command sequence replayed across sessions. `CORRELATED`.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.db.models import Analysis, TechniqueMapping
from app.db.session import get_session_factory
from app.models.notable import Notable
from app.services.campaigns import list_campaigns
from app.services.session_builder import honeypots_for_sessions

_HIGH_RISK = ("high", "critical")

# A replay worth interrupting someone for. Two sessions is a coincidence or a
# retry as often as it is a campaign.
_CAMPAIGN_MIN_SESSIONS = 3

_MAX_NOTABLES = 50


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


async def list_notables(days: int = 7, deny_honeypots: set[str] | None = None) -> list[Notable]:
    since = datetime.now(UTC) - timedelta(days=days)
    async with get_session_factory()() as db:
        analyses = (
            (
                await db.execute(
                    select(Analysis)
                    .where(Analysis.risk.in_(_HIGH_RISK), Analysis.created_at >= since)
                    .order_by(Analysis.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        # Every rule-backed mapping ever, not just recent ones: "first seen" is
        # only decidable against the whole history.
        rule_rows = (
            await db.execute(
                select(TechniqueMapping, Analysis.session_id)
                .join(Analysis, Analysis.id == TechniqueMapping.analysis_id)
                .where(TechniqueMapping.source == "rule")
            )
        ).all()

    sessions = {a.session_id for a in analyses} | {sid for _, sid in rule_rows}
    owners = await honeypots_for_sessions(sorted(sessions)) if deny_honeypots else {}

    def readable(session_id: str) -> bool:
        # Same rule as `analyzer.load_history`: under a scope, a session that
        # cannot be placed on a sensor is not shown.
        if not deny_honeypots:
            return True
        return session_id in owners and owners[session_id] not in deny_honeypots

    notables: list[Notable] = []

    seen_sessions: set[str] = set()
    for analysis in analyses:  # newest first, so the first per session is its latest
        if analysis.session_id in seen_sessions or not readable(analysis.session_id):
            continue
        seen_sessions.add(analysis.session_id)
        notables.append(
            Notable(
                id=f"high_risk_session:{analysis.session_id}",
                kind="high_risk_session",
                provenance="AI INFERENCE",
                title=f"{analysis.risk.capitalize()} risk: {analysis.classification}",
                detail=f"Model-rated {analysis.risk_score}/100 for session {analysis.session_id}",
                timestamp=_iso(analysis.created_at),
                session_id=analysis.session_id,
            )
        )

    # First sighting among the sessions THIS caller may read. Computing it over
    # every sensor would let a hidden sensor's earlier sighting suppress -- and
    # so reveal -- a notable here.
    first: dict[str, tuple[TechniqueMapping, str]] = {}
    for mapping, session_id in rule_rows:
        if not readable(session_id):
            continue
        current = first.get(mapping.technique_id)
        if current is None or mapping.timestamp < current[0].timestamp:
            first[mapping.technique_id] = (mapping, session_id)
    for mapping, session_id in first.values():
        if mapping.timestamp < since:
            continue
        notables.append(
            Notable(
                id=f"technique_first_seen:{mapping.technique_id}",
                kind="technique_first_seen",
                provenance="OBSERVED",
                title=f"First observation of {mapping.technique_id} {mapping.technique_name}",
                detail=f"Matched by rule {mapping.rule_id} in session {session_id}",
                timestamp=_iso(mapping.timestamp),
                session_id=session_id,
                technique_id=mapping.technique_id,
            )
        )

    for campaign in (await list_campaigns(deny_honeypots=deny_honeypots)).campaigns:
        if campaign.session_count < _CAMPAIGN_MIN_SESSIONS:
            continue
        if datetime.fromisoformat(campaign.last_seen) < since:
            continue
        notables.append(
            Notable(
                id=f"campaign:{campaign.fingerprint}",
                kind="campaign",
                provenance="CORRELATED",
                title=f"Campaign {campaign.fingerprint}: {campaign.session_count} sessions",
                detail=(
                    f"The same {campaign.command_count}-command sequence from "
                    f"{campaign.attacker_ip_count} source address(es)"
                ),
                timestamp=campaign.last_seen,
            )
        )

    def newest(items: list[Notable]) -> list[Notable]:
        # Parsed, not compared as strings: Elasticsearch and Postgres format
        # fractional seconds differently, which mis-orders two items in the same second.
        return sorted(items, key=lambda n: datetime.fromisoformat(n.timestamp), reverse=True)

    # A burst of high-risk sessions must not crowd out the rare kinds. A first
    # sighting or a campaign is what the bell exists for and there are a few
    # dozen at most, while sessions arrive by the hundred (2026-10-19: one batch
    # of 48 pushed a first sighting off a plain newest-50 list).
    rare = newest([n for n in notables if n.kind != "high_risk_session"])[:_MAX_NOTABLES]
    sessions = [n for n in notables if n.kind == "high_risk_session"]
    return newest(rare + newest(sessions)[: _MAX_NOTABLES - len(rare)])
