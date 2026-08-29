from app.config import get_settings
from app.es.client import get_es
from app.models.event import HoneypotEvent, LogQuery, Paginated

_TERM_FIELDS = {
    "honeypot_id": "honeypot.id",
    "source_ip": "source.ip",
    "destination_ip": "destination.ip",
    "protocol": "network.protocol",
    "event_category": "event.category",
    "risk": "risk.level",
    "technique_id": "mitre.technique_id",
    "session_id": "session.id",
}


def build_log_query(query: LogQuery) -> dict:
    """Translate the frontend's LogQuery into an Elasticsearch bool query."""
    filters: list[dict] = []
    must: list[dict] = []

    for attr, field in _TERM_FIELDS.items():
        value = getattr(query, attr)
        if value:
            filters.append({"term": {field: value}})

    if query.from_ or query.to:
        bounds: dict[str, str] = {}
        if query.from_:
            bounds["gte"] = query.from_
        if query.to:
            bounds["lte"] = query.to
        filters.append({"range": {"@timestamp": bounds}})

    if query.q:
        must.append(
            {
                "multi_match": {
                    "query": query.q,
                    "fields": [
                        "process.command_line",
                        "event.action",
                        "user.name",
                        "source.ip",
                    ],
                    # source.ip is mapped as `ip`, not `text`/`keyword`. Without
                    # `lenient` a query string that isn't a valid IP literal
                    # (e.g. "wget") makes ES reject the whole multi_match with a
                    # 400 instead of just skipping that field. Including the
                    # field keeps free-text search consistent with the sessions
                    # surface, where pasting an attacker IP already works.
                    "lenient": True,
                }
            }
        )

    return {"bool": {"filter": filters, "must": must}}


def to_event(hit: dict) -> HoneypotEvent:
    src = hit["_source"]
    process = src.get("process")
    mitre = src.get("mitre")
    return HoneypotEvent.model_validate(
        {
            "id": hit["_id"],
            "timestamp": src.get("@timestamp", ""),
            "source": src.get("source") or {"ip": "0.0.0.0"},
            "destination": src.get("destination") or {},
            "event": src.get("event") or {"action": "unknown", "category": "other"},
            "network": src.get("network") or {"protocol": "ssh"},
            "user": src.get("user"),
            "process": (
                {
                    "commandLine": process.get("command_line"),
                    "output": process.get("output"),
                }
                if process
                else None
            ),
            "file": src.get("file"),
            "honeypot": src.get("honeypot") or {"id": "unknown", "name": "unknown"},
            "session": src.get("session") or {"id": "unknown"},
            "risk": src.get("risk") or {"score": 0, "level": "informational"},
            "mitre": (
                {
                    "techniqueId": mitre.get("technique_id"),
                    "tactic": mitre.get("tactic"),
                }
                if mitre
                else None
            ),
            "aiClassification": src.get("ai_classification"),
        }
    )


async def search_logs(query: LogQuery) -> Paginated[HoneypotEvent]:
    settings = get_settings()
    page = max(query.page, 1)
    size = min(max(query.page_size, 1), 500)

    result = await get_es().search(
        index=settings.es_index,
        query=build_log_query(query),
        sort=[{"@timestamp": "asc"}],
        from_=(page - 1) * size,
        size=size,
        track_total_hits=True,
    )

    return Paginated[HoneypotEvent](
        items=[to_event(h) for h in result["hits"]["hits"]],
        total=result["hits"]["total"]["value"],
        page=page,
        page_size=size,
    )


async def get_event_by_id(event_id: str) -> HoneypotEvent | None:
    """Resolve one event. Backs GET /api/events/{id} and evidence lookups."""
    result = await get_es().search(
        index=get_settings().es_index,
        query={"ids": {"values": [event_id]}},
        size=1,
    )
    hits = result["hits"]["hits"]
    return to_event(hits[0]) if hits else None
