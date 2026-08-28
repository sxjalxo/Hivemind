from datetime import datetime

from app.config import get_settings
from app.es.client import get_es
from app.es.queries import to_event
from app.models.event import HoneypotEvent
from app.models.session import AttackSession, SessionTimelineEvent

_COMMAND_ACTION = "cowrie.command.input"

_KIND_BY_ACTION = {
    "cowrie.session.connect": "connection",
    "cowrie.session.closed": "disconnect",
    "cowrie.login.success": "auth",
    "cowrie.login.failed": "auth",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command",
    "cowrie.session.file_download": "download",
    "cowrie.session.file_upload": "file",
}


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


async def _fetch_session_events(session_id: str) -> list[HoneypotEvent]:
    result = await get_es().search(
        index=get_settings().es_index,
        query={"term": {"session.id": session_id}},
        sort=[{"@timestamp": "asc"}],
        size=1000,
    )
    return [to_event(h) for h in result["hits"]["hits"]]


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
        source_port=first.source.port or 0,
        destination_port=next(
            (e.destination.port for e in events if e.destination.port), 0
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
    return _assemble(session_id, events) if events else None


async def list_sessions(
    risk: str | None = None,
    honeypot_id: str | None = None,
    q: str | None = None,
) -> list[AttackSession]:
    """Find session ids matching the filters, then assemble each one."""
    filters: list[dict] = []
    if honeypot_id:
        filters.append({"term": {"honeypot.id": honeypot_id}})
    if risk:
        filters.append({"term": {"risk.level": risk}})

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

    result = await get_es().search(
        index=get_settings().es_index,
        query={"bool": {"filter": filters, "must": must}},
        size=0,
        aggs={
            "sessions": {
                "terms": {"field": "session.id", "size": 500},
                "aggs": {"first_seen": {"min": {"field": "@timestamp"}}},
            }
        },
    )

    buckets = result["aggregations"]["sessions"]["buckets"]
    buckets.sort(key=lambda b: b["first_seen"]["value"], reverse=True)

    sessions: list[AttackSession] = []
    for bucket in buckets:
        session = await get_session(bucket["key"])
        if session:
            sessions.append(session)
    return sessions


async def build_timeline(session_id: str) -> list[SessionTimelineEvent]:
    events = await _fetch_session_events(session_id)
    timeline: list[SessionTimelineEvent] = []

    for event in events:
        action = event.event.action
        kind = _KIND_BY_ACTION.get(action, "command")

        if kind == "command" and event.process and event.process.command_line:
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
                detail=None if kind == "command" else action,
                severity=event.risk.level,
                technique_id=event.mitre.technique_id if event.mitre else None,
            )
        )
    return timeline
