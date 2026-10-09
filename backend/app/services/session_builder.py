import logging
from datetime import datetime

from app.config import get_settings
from app.es.client import get_es
from app.es.queries import to_event
from app.models.event import HoneypotEvent
from app.models.session import AttackSession, SessionTimelineEvent

logger = logging.getLogger(__name__)

_COMMAND_ACTION = "cowrie.command.input"

# One Elasticsearch page. Cowrie sessions run to tens of events, so this is
# headroom rather than a limit anyone meets -- but it IS a limit, and a session
# past it lost its tail with nothing said: a short timeline, an understated
# command count, and a compaction the model would read as the whole session.
# Reaching it is loud now; raising it or paging is a deliberate change, not a
# number to nudge when a warning appears.
_MAX_SESSION_EVENTS = 1000

# Ceiling on the session-list aggregation, independent of what a caller asks
# for. Reaching it is reported rather than silently truncating the fleet.
_MAX_SESSION_BUCKETS = 500

_KIND_BY_ACTION = {
    "cowrie.session.connect": "connection",
    "cowrie.session.closed": "disconnect",
    "cowrie.login.success": "auth",
    "cowrie.login.failed": "auth",
    "cowrie.command.input": "command",
    # A command Cowrie could not resolve. It is an execution attempt, not a
    # second thing the attacker typed: Cowrie emits it alongside the
    # `cowrie.command.input` for the same keystrokes, so counting it as a
    # command would show more commands in the timeline than the session
    # header reports.
    "cowrie.command.failed": "execution",
    "cowrie.session.file_download": "download",
    "cowrie.session.file_upload": "file",
    # SSH transport and session metadata that Cowrie records for every real
    # connection. None of it is attacker input.
    "cowrie.client.version": "protocol",
    "cowrie.client.kex": "protocol",
    "cowrie.client.size": "protocol",
    "cowrie.client.var": "protocol",
    "cowrie.client.fingerprint": "protocol",
    "cowrie.session.params": "protocol",
    "cowrie.log.closed": "protocol",
    # Port forwarding is the attacker asking the honeypot to relay traffic on
    # their behalf (ATT&CK T1090). It is an action they took, not transport
    # metadata the daemon recorded, and burying it next to the key exchange
    # would hide the honeypot being used as a proxy.
    "cowrie.direct-tcpip.request": "tunnel",
    "cowrie.direct-tcpip.data": "tunnel",
}

# Anything this module does not recognise is reported as "other" rather than
# guessed at. The previous default was "command", which meant every eventid
# absent from the map above was rendered to the analyst as a command the
# attacker typed. The seed corpus contains only mapped eventids, so the
# fallback was never exercised until live Cowrie traffic arrived carrying the
# protocol events above -- four fabricated command rows per session.
_UNKNOWN_KIND = "other"

# Kinds whose label is the command line the attacker submitted.
_COMMAND_LINE_KINDS = {"command", "execution"}


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


async def _fetch_session_events(session_id: str) -> list[HoneypotEvent]:
    result = await get_es().search(
        index=get_settings().es_index,
        query={"term": {"session.id": session_id}},
        sort=[{"@timestamp": "asc"}],
        size=_MAX_SESSION_EVENTS,
    )
    hits = result["hits"]["hits"]
    # ES caps `total.value` at 10 000 by default and marks it `gte`, so this
    # under-reports a very large session -- it still exceeds `len(hits)`, which
    # is the only comparison being made.
    total = result["hits"].get("total", {}).get("value", len(hits))
    if total > len(hits):
        logger.warning(
            "session %s truncated at %d of %d events: its timeline, command count "
            "and any analysis of it describe only the first page",
            session_id,
            len(hits),
            total,
        )
    return [to_event(h) for h in hits]


def _assemble(session_id: str, events: list[HoneypotEvent]) -> AttackSession:
    """Build an AttackSession from its ordered events.

    Analysis-derived fields stay empty; Task 14 overlays them once an
    analysis exists. An unanalyzed session never shows invented values.
    """
    first, last = events[0], events[-1]
    commands = [e for e in events if e.event.action == _COMMAND_ACTION]
    username = next(
        (e.user.name for e in events if e.user and e.user.name),
        None,
    )
    closed = any(e.event.action == "cowrie.session.closed" for e in events)

    return AttackSession(
        id=session_id,
        attacker_ip=first.source.ip,
        source_port=first.source.port,
        destination_port=next(
            (e.destination.port for e in events if e.destination.port), None
        ),
        honeypot_id=first.honeypot.id,
        honeypot_name=first.honeypot.name,
        protocol=first.network.protocol,
        started_at=first.timestamp,
        ended_at=last.timestamp if closed else None,
        duration_seconds=int((_parse(last.timestamp) - _parse(first.timestamp)).total_seconds()),
        command_count=len(commands),
        risk_score=0,
        risk="informational",
        classification_chain=[],
        mitre_technique_ids=[],
        analysis_state="not_analyzed",
        country=first.source.country,
        username=username,
    )


async def get_session_events(session_id: str) -> list[HoneypotEvent]:
    return await _fetch_session_events(session_id)


async def get_session(session_id: str) -> AttackSession | None:
    events = await _fetch_session_events(session_id)
    if not events:
        return None

    session = _assemble(session_id, events)

    # Local import: analyzer imports session_builder (get_session_events),
    # so a module-level import here would be circular.
    from app.services.analyzer import latest_for_session

    analysis = await latest_for_session(session_id)
    if analysis:
        session.analysis_state = "completed"
        # `risk` and `risk_score` are the MODEL's, copied onto the session --
        # there is no deterministic scorer, and `_assemble` leaves them 0 /
        # "informational" until an analysis exists. They are not evidence-gated
        # (see `compaction.build_prompt`) and move between runs of one session,
        # so anything rendering them must label them as inference. The session
        # page once captioned this value "scored from recorded session
        # behaviour before any LLM interpretation", which was exactly backwards.
        session.risk = analysis.risk
        session.risk_score = analysis.risk_score
        session.mitre_technique_ids = [t.technique_id for t in analysis.techniques]
        seen: list[str] = []
        for technique in analysis.techniques:
            if technique.tactic not in seen:
                seen.append(technique.tactic)
        session.classification_chain = seen
    return session


async def list_sessions(
    risk: str | None = None,
    honeypot_id: str | None = None,
    q: str | None = None,
    limit: int | None = None,
    deny_honeypots: set[str] | None = None,
) -> list[AttackSession]:
    """Find session ids matching the filters, then assemble each one.

    `limit` is None for internal callers and set by the route. It is not
    cosmetic: `get_session` below costs two Elasticsearch round trips per
    session, run sequentially, so an unbounded list made the slowest request
    in the API grow with the corpus rather than with the question asked.
    """
    filters: list[dict] = []
    if honeypot_id:
        filters.append({"term": {"honeypot.id": honeypot_id}})
    if risk:
        filters.append({"term": {"risk.level": risk}})

    # Applied in the query, not by dropping rows afterwards: a denied honeypot
    # must not reach the aggregation either, or its sessions consume buckets
    # from the caller's page and the list comes back short for no visible
    # reason.
    must_not: list[dict] = []
    if deny_honeypots:
        must_not.append({"terms": {"honeypot.id": sorted(deny_honeypots)}})

    must: list[dict] = []
    if q:
        must.append(
            {
                "multi_match": {
                    "query": q,
                    "fields": ["process.command_line", "user.name", "source.ip"],
                    # source.ip is mapped as `ip`, not `text`/`keyword`; without
                    # `lenient` a query string that isn't a valid IP literal
                    # (e.g. a command fragment like "xmrig_setup") makes ES
                    # reject the whole multi_match with a 400 instead of just
                    # skipping that field for scoring.
                    "lenient": True,
                }
            }
        )

    # `must_not` only when something is excluded, so an unscoped query keeps
    # the shape it has always had rather than growing an empty clause.
    bool_query: dict = {"filter": filters, "must": must}
    if must_not:
        bool_query["must_not"] = must_not

    wanted = _MAX_SESSION_BUCKETS if limit is None else min(limit, _MAX_SESSION_BUCKETS)
    result = await get_es().search(
        index=get_settings().es_index,
        query={"bool": bool_query},
        size=0,
        aggs={
            "sessions": {
                # Ordered by `first_seen`, NOT by doc count. A terms aggregation
                # defaults to the biggest buckets, so the cap used to keep the
                # NOISIEST sessions and drop quiet ones -- including the most
                # recent -- and the sort below then presented that selection as
                # if it were "the latest sessions". Ordering here makes the cap
                # mean what the list claims: the newest `wanted` sessions.
                "terms": {
                    "field": "session.id",
                    "size": wanted,
                    "order": {"first_seen": "desc"},
                },
                "aggs": {"first_seen": {"min": {"field": "@timestamp"}}},
            }
        },
    )

    aggregation = result["aggregations"]["sessions"]
    buckets = aggregation["buckets"]
    buckets.sort(key=lambda b: b["first_seen"]["value"], reverse=True)

    # Anything the cap left behind. Silence here read as a short fleet rather
    # than a truncated answer -- and the caller cannot tell the two apart from
    # the response, which is a list either way.
    dropped = aggregation.get("sum_other_doc_count", 0)
    if dropped:
        logger.warning(
            "session list truncated at %d: %d further events belong to sessions "
            "outside this page",
            len(buckets),
            dropped,
        )

    sessions: list[AttackSession] = []
    for bucket in buckets:
        session = await get_session(bucket["key"])
        if session:
            sessions.append(session)
    return sessions


async def honeypots_for_sessions(session_ids: list[str]) -> dict[str, str]:
    """Map each session id to the honeypot that recorded it, in one query.

    `analyses` stores a session id and no honeypot, so scoping an analysis
    read means asking Elasticsearch which sensor the session came from. One
    aggregation for the whole page rather than `get_session` per row: that
    would be two round trips per analysis, which is the N+1 the list route's
    limit exists to avoid in the first place.

    A session id absent from the result is simply omitted -- its events have
    aged out of the index, and a caller scoping reads must treat an id it
    cannot place as one it cannot show.
    """
    if not session_ids:
        return {}
    result = await get_es().search(
        index=get_settings().es_index,
        query={"terms": {"session.id": sorted(set(session_ids))}},
        size=0,
        aggs={
            "sessions": {
                "terms": {"field": "session.id", "size": len(set(session_ids))},
                "aggs": {"honeypot": {"terms": {"field": "honeypot.id", "size": 1}}},
            }
        },
    )
    mapping: dict[str, str] = {}
    for bucket in result["aggregations"]["sessions"]["buckets"]:
        honeypots = bucket["honeypot"]["buckets"]
        if honeypots:
            mapping[bucket["key"]] = honeypots[0]["key"]
    return mapping


async def build_timeline(session_id: str) -> list[SessionTimelineEvent]:
    events = await _fetch_session_events(session_id)
    timeline: list[SessionTimelineEvent] = []

    for event in events:
        action = event.event.action
        kind = _KIND_BY_ACTION.get(action, _UNKNOWN_KIND)

        if kind in _COMMAND_LINE_KINDS and event.process and event.process.command_line:
            label = event.process.command_line
        elif kind == "auth":
            outcome = "succeeded" if action.endswith("success") else "failed"
            label = f"Login {outcome}"
        elif kind == "connection":
            label = f"Connection from {event.source.ip}"
        elif kind == "disconnect":
            label = "Session closed"
        else:
            label = action

        timeline.append(
            SessionTimelineEvent(
                id=event.id,
                timestamp=event.timestamp,
                kind=kind,
                label=label,
                # The eventid adds nothing next to a command line, and
                # repeating it under a label that already IS the eventid
                # renders the same string twice.
                detail=None if kind == "command" or label == action else action,
                severity=event.risk.level,
                technique_id=event.mitre.technique_id if event.mitre else None,
            )
        )
    return timeline
