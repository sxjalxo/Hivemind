from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.es.client import get_es
from app.models.dashboard import (
    DashboardData,
    DashboardKpi,
    NamedValue,
    RiskBucket,
    TimelinePoint,
    TopAttacker,
    TopCommand,
)
from app.models.honeypot import Honeypot

_WINDOWS = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}

_BUCKET_INTERVAL = {"1h": "5m", "24h": "1h", "7d": "12h", "30d": "1d"}

_RISK_LEVELS = ["critical", "high", "medium", "low", "informational"]


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def range_to_bounds(range_: str) -> tuple[str, str]:
    """Resolve a UI range string to (start, end) ISO timestamps."""
    span = _WINDOWS.get(range_, _WINDOWS["24h"])
    end = datetime.now(timezone.utc)
    return _iso(end - span), _iso(end)


def _previous_bounds(range_: str) -> tuple[str, str]:
    span = _WINDOWS.get(range_, _WINDOWS["24h"])
    end = datetime.now(timezone.utc) - span
    return _iso(end - span), _iso(end)


def _range_filter(start: str, end: str, *, inclusive_end: bool = True) -> dict:
    """Build a range filter. Half-open (`lt`) when the caller needs windows
    that partition cleanly instead of sharing a boundary instant."""
    upper_op = "lte" if inclusive_end else "lt"
    return {"range": {"@timestamp": {"gte": start, upper_op: end}}}


def _epoch_millis(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


def _trend(current: int, previous: int) -> tuple[float, str]:
    """Percentage change. A zero baseline yields flat, never a fabricated jump."""
    if previous == 0:
        return 0.0, "flat"
    pct = round((current - previous) / previous * 100, 1)
    if pct > 0:
        return pct, "up"
    if pct < 0:
        return pct, "down"
    return 0.0, "flat"


async def list_honeypots() -> list[Honeypot]:
    """Derive honeypot inventory from indexed events.

    There is no separate registry: a honeypot exists because its events do.
    """
    settings = get_settings()
    result = await get_es().search(
        index=settings.es_index,
        size=0,
        aggs={
            "honeypots": {
                "terms": {"field": "honeypot.id", "size": 50},
                "aggs": {
                    "name": {"terms": {"field": "honeypot.name", "size": 1}},
                    "last_activity": {"max": {"field": "@timestamp"}},
                    "sessions": {"cardinality": {"field": "session.id"}},
                    "dst_ip": {"terms": {"field": "destination.ip", "size": 1}},
                },
            }
        },
    )

    now = datetime.now(timezone.utc)
    honeypots: list[Honeypot] = []
    for bucket in result["aggregations"]["honeypots"]["buckets"]:
        name_buckets = bucket["name"]["buckets"]
        dst_ip_buckets = bucket["dst_ip"]["buckets"]
        last_iso = bucket["last_activity"]["value_as_string"]
        stale = (now - datetime.fromisoformat(last_iso.replace("Z", "+00:00"))) > timedelta(hours=24)
        honeypots.append(
            Honeypot(
                id=bucket["key"],
                name=name_buckets[0]["key"] if name_buckets else bucket["key"],
                type="SSH",
                os="Debian 11 (emulated)",
                interaction_level="medium",
                # Observed from indexed events, not a fabricated address.
                # "unknown" (never a made-up IP) is the honest fallback for
                # a honeypot bucket that somehow has no destination.ip on
                # any of its documents.
                ip=dst_ip_buckets[0]["key"] if dst_ip_buckets else "unknown",
                status="degraded" if stale else "online",
                active_sessions=bucket["sessions"]["value"],
                events=bucket["doc_count"],
                last_activity=last_iso,
                # risk.level is unassessed until Task 14 writes real
                # analysis back to events; "informational" is this
                # codebase's convention for "not yet assessed" (see
                # to_event in app.es.queries and _assemble in
                # app.services.session_builder), never a fabricated
                # severity like "medium".
                risk="informational",
                sensor=bucket["key"],
            )
        )
    return honeypots


async def build_dashboard(range_: str) -> DashboardData:
    settings = get_settings()
    start, end = range_to_bounds(range_)
    prev_start, prev_end = _previous_bounds(range_)
    window = _range_filter(start, end)
    # min_doc_count: 0 only fills gaps BETWEEN observed documents; it does
    # not extend the histogram to the query's actual start/end. Without
    # explicit bounds a sparse window (e.g. seed data clustered on one day
    # inside a 30d range) renders an axis that silently starts wherever
    # data happens to begin, and a window with zero matching documents
    # renders no buckets at all. extended_bounds forces the full requested
    # span to appear (with zero-valued buckets where there's no data);
    # hard_bounds clips out anything outside it for good measure.
    bounds = {"min": _epoch_millis(start), "max": _epoch_millis(end)}

    result = await get_es().search(
        index=settings.es_index,
        query={"bool": {"filter": [window]}},
        size=0,
        track_total_hits=True,
        aggs={
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": _BUCKET_INTERVAL.get(range_, "1h"),
                    "min_doc_count": 0,
                    "extended_bounds": bounds,
                    "hard_bounds": bounds,
                },
                "aggs": {
                    "high_risk": {
                        "filter": {"terms": {"risk.level": ["critical", "high"]}}
                    }
                },
            },
            "sessions": {"cardinality": {"field": "session.id"}},
            "risk_levels": {"terms": {"field": "risk.level", "size": 10}},
            "classifications": {"terms": {"field": "ai_classification", "size": 10}},
            "techniques": {"cardinality": {"field": "mitre.technique_id"}},
            "high_risk": {"filter": {"terms": {"risk.level": ["critical", "high"]}}},
            "attackers": {
                "terms": {"field": "source.ip", "size": 10},
                "aggs": {
                    "sessions": {"cardinality": {"field": "session.id"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "country": {"terms": {"field": "source.country", "size": 1}},
                },
            },
            "commands": {
                "terms": {"field": "process.command_line.keyword", "size": 10},
                "aggs": {"technique": {"terms": {"field": "mitre.technique_id", "size": 1}}},
            },
        },
    )

    # prev_end == start (the current window's lower bound): make the
    # previous window's upper edge exclusive so the two windows partition
    # cleanly instead of double-counting a document landing exactly on
    # that shared boundary instant.
    previous = await get_es().count(
        index=settings.es_index,
        query={
            "bool": {
                "filter": [_range_filter(prev_start, prev_end, inclusive_end=False)]
            }
        },
    )

    aggs = result["aggregations"]
    total_events = result["hits"]["total"]["value"]
    high_risk = aggs["high_risk"]["doc_count"]
    sessions = aggs["sessions"]["value"]
    techniques = aggs["techniques"]["value"]

    events_pct, events_dir = _trend(total_events, int(previous["count"]))

    kpis = [
        DashboardKpi(
            id="total_events",
            label="Total events",
            value=total_events,
            trend_pct=events_pct,
            trend_direction=events_dir,
            tone="default",
        ),
        DashboardKpi(
            id="active_sessions",
            label="Sessions",
            value=sessions,
            trend_pct=0.0,
            trend_direction="flat",
            tone="info",
        ),
        DashboardKpi(
            id="high_risk",
            label="High-risk events",
            value=high_risk,
            trend_pct=0.0,
            trend_direction="flat",
            tone="critical",
        ),
        DashboardKpi(
            id="techniques",
            label="ATT&CK techniques",
            value=techniques,
            trend_pct=0.0,
            trend_direction="flat",
            tone="ai",
        ),
    ]

    timeline = [
        TimelinePoint(
            t=b["key_as_string"],
            events=b["doc_count"],
            high_risk=b["high_risk"]["doc_count"],
        )
        for b in aggs["over_time"]["buckets"]
    ]

    observed_risk = {b["key"]: b["doc_count"] for b in aggs["risk_levels"]["buckets"]}
    risk_distribution = [
        RiskBucket(level=level, value=observed_risk.get(level, 0)) for level in _RISK_LEVELS
    ]

    classifications = [
        NamedValue(name=b["key"], value=b["doc_count"])
        for b in aggs["classifications"]["buckets"]
    ]

    top_attackers = []
    for b in aggs["attackers"]["buckets"]:
        country_buckets = b["country"]["buckets"]
        top_attackers.append(
            TopAttacker(
                ip=b["key"],
                country=country_buckets[0]["key"] if country_buckets else "Unknown",
                events=b["doc_count"],
                sessions=b["sessions"]["value"],
                # Not yet assessed — see the risk="informational" note in
                # list_honeypots above; the same convention applies here.
                risk="informational",
                last_seen=b["last_seen"]["value_as_string"],
            )
        )

    top_commands = []
    for b in aggs["commands"]["buckets"]:
        technique_buckets = b["technique"]["buckets"]
        top_commands.append(
            TopCommand(
                command=b["key"],
                count=b["doc_count"],
                technique_id=technique_buckets[0]["key"] if technique_buckets else None,
            )
        )

    return DashboardData(
        kpis=kpis,
        timeline=timeline,
        classifications=classifications,
        risk_distribution=risk_distribution,
        top_attackers=top_attackers,
        top_commands=top_commands,
    )
