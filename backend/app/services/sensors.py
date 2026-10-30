"""What a sensor is, as observed and as derived (roadmap R2).

Every described value names its source; nothing is a placeholder.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from sqlalchemy import select

from app.config import get_settings
from app.db.models import (
    EvaluationProbeResult,
    EvaluationRun,
    PersonaDeployment,
    SensorChange,
)
from app.db.session import get_session_factory
from app.es.client import get_es
from app.models.sensor import (
    ChangeOut,
    DayPoint,
    DeploymentOut,
    Described,
    PeriodOut,
    PeriodTraffic,
    SensorProfile,
    SensorTechniques,
    SensorTraffic,
    SourceOut,
    TechniqueOut,
)
from app.services import persona_deployments, sensor_changes
from app.services.compaction import CompactedCommand
from app.services.evaluation import sanity
from app.services.mitre import rules
from app.services.periods import periods

_PERSONAS = Path(__file__).resolve().parents[3] / "infra" / "cowrie" / "personas"
_PROTOCOL_NAMES = {"ssh": "SSH", "telnet": "Telnet", "http": "HTTP"}
_UNKNOWN = Described(value="unknown", source="unknown")


def describe_type(protocols: dict[str, int]) -> Described:
    """The protocols a sensor has served, most frequent first."""
    if not protocols:
        return _UNKNOWN
    ordered = sorted(protocols, key=lambda p: -protocols[p])
    names = [_PROTOCOL_NAMES.get(p, p.upper()) for p in ordered]
    return Described(value=", ".join(names), source="observed")


def _persona_os(persona: str) -> str:
    try:
        facts = yaml.safe_load((_PERSONAS / persona / "persona.yaml").read_text(encoding="utf-8"))
        return facts["distro"]["pretty_name"]
    except (OSError, KeyError, TypeError):
        return persona  # the persona is known, its description is not


async def _evaluated_os(honeypot_id: str, since: datetime | None = None) -> str | None:
    """The first readable `os.identity` claim of the latest completed evaluation.

    `since`: ignore runs that started before it (a run made under an earlier
    persona says nothing about the setup now in force).
    """
    query = (
        select(EvaluationRun.id)
        .where(EvaluationRun.honeypot_id == honeypot_id)
        .where(EvaluationRun.status == "completed")
    )
    if since is not None:
        query = query.where(EvaluationRun.started_at >= since)
    async with get_session_factory()() as db:
        run_id = (
            await db.execute(query.order_by(EvaluationRun.started_at.desc()).limit(1))
        ).scalar_one_or_none()
        if run_id is None:
            return None
        rows = (
            await db.execute(
                select(EvaluationProbeResult)
                .where(EvaluationProbeResult.run_id == run_id)
                .where(EvaluationProbeResult.establishes == "os.identity")
                .where(EvaluationProbeResult.fact_status == "observed")
                .order_by(EvaluationProbeResult.probe_id)
            )
        ).scalars()
        extracts = sanity.probe_extracts()
        for row in rows:
            claim = sanity.comparable_value(
                sanity.Observation(
                    probe_id=row.probe_id,
                    establishes=row.establishes,
                    value=row.value,
                    fact_status=row.fact_status,
                ),
                extracts,
            )
            if claim:
                return claim.capitalize()
    return None


async def describe_os(honeypot_id: str) -> Described:
    """Active persona, else the observed claim of an evaluation since the setup in force, else unknown."""
    active = await persona_deployments.active(honeypot_id)
    if active and active.persona != persona_deployments.PRE_PERSONA:
        return Described(value=_persona_os(active.persona), source="persona")
    # Only runs made since the setup now in force count (also after a revert).
    claim = await _evaluated_os(honeypot_id, since=active.deployed_at if active else None)
    return Described(value=claim, source="evaluation") if claim else _UNKNOWN


def _parse(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


async def get_profile(honeypot_id: str) -> SensorProfile | None:
    result = await get_es().search(
        index=get_settings().es_index,
        query={"term": {"honeypot.id": honeypot_id}},
        size=0,
        track_total_hits=True,
        aggs={
            "protocols": {"terms": {"field": "network.protocol", "size": 10}},
            "address": {"terms": {"field": "destination.ip", "size": 1}},
            "name": {"terms": {"field": "honeypot.name", "size": 1}},
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
        },
    )
    if result["hits"]["total"]["value"] == 0:
        return None
    aggs = result["aggregations"]
    protocols = {b["key"]: b["doc_count"] for b in aggs["protocols"]["buckets"]}
    names, addresses = aggs["name"]["buckets"], aggs["address"]["buckets"]
    first, last = _parse(aggs["first"]["value_as_string"]), _parse(aggs["last"]["value_as_string"])
    deployments = await persona_deployments.history(honeypot_id)
    changes = await sensor_changes.history(honeypot_id)
    return SensorProfile(
        id=honeypot_id,
        name=names[0]["key"] if names else honeypot_id,
        protocols=protocols,
        address=addresses[0]["key"] if addresses else "unknown",
        first_seen=first,
        last_seen=last,
        type=describe_type(protocols),
        os=await describe_os(honeypot_id),
        deployments=[DeploymentOut.model_validate(d) for d in deployments],
        changes=[ChangeOut.model_validate(c) for c in changes],
        periods=_period_outs(deployments, changes, first, datetime.now(UTC)),
    )


def _period_outs(
    deployments: list[PersonaDeployment],
    changes: list[SensorChange],
    start: datetime,
    end: datetime,
) -> list[PeriodOut]:
    return [
        PeriodOut(start=p.start, end=p.end, persona=p.persona, opened_by=list(p.opened_by))
        for p in periods(deployments, changes, start, end)
    ]


def _per_day(count: int, span: PeriodOut) -> float:
    """A count over the period's length in days (at least an hour, so a sliver does not explode)."""
    return count / max((span.end - span.start).total_seconds() / 86400, 1 / 24)


@dataclass
class _Window:
    """The last `days`, cut into periods, and the one search shape every windowed view shares."""

    start: datetime
    end: datetime
    deployments: list[PersonaDeployment]
    changes: list[SensorChange]
    spans: list[PeriodOut]  # over the whole window; see clip()

    @classmethod
    async def of(cls, honeypot_id: str, days: int) -> "_Window":
        end = datetime.now(UTC)
        start = end - timedelta(days=days)
        deployments = await persona_deployments.history(honeypot_id)
        changes = await sensor_changes.history(honeypot_id)
        # Cut over the whole window so the range agg can ask for them in the one search;
        # the leading ones that end before the first event are dropped once it is known.
        return cls(start, end, deployments, changes, _period_outs(deployments, changes, start, end))

    def filter(self, *extra: dict) -> dict:
        window = {
            "range": {"@timestamp": {"gte": self.start.isoformat(), "lte": self.end.isoformat()}}
        }
        return {"bool": {"filter": [window, *extra]}}

    def by_period(self, aggs: dict) -> dict:
        return {
            "range": {
                "field": "@timestamp",
                "ranges": [
                    {"from": s.start.isoformat(), "to": s.end.isoformat()} for s in self.spans
                ],
            },
            "aggs": aggs,
        }

    async def search(self, honeypot_id: str, window_aggs: dict, *extra: dict) -> dict | None:
        """The sensor's first event plus `window_aggs` over the window (filtered by `extra`).

        None only when the sensor has no events at all; a quiet window is empty aggregations.
        """
        result = await get_es().search(
            index=get_settings().es_index,
            query={"term": {"honeypot.id": honeypot_id}},
            size=0,
            track_total_hits=True,
            aggs={
                "first": {"min": {"field": "@timestamp"}},
                "window": {"filter": self.filter(*extra), "aggs": window_aggs},
            },
        )
        return None if result["hits"]["total"]["value"] == 0 else result["aggregations"]

    def clip(self, aggregations: dict) -> tuple[list[PeriodOut], int]:
        """The periods from the sensor's first event on, and how many leading `by_period` buckets to skip."""
        first = _parse(aggregations["first"]["value_as_string"])
        spans = _period_outs(self.deployments, self.changes, max(self.start, first), self.end)
        return spans, len(self.spans) - len(spans)


async def get_traffic(honeypot_id: str, days: int) -> SensorTraffic | None:
    """Per-day, per-source, per-protocol and per-period traffic over the last `days`.

    None only when the sensor has no events at all; a quiet window is zeros.
    The per-day chart spans the whole window; the periods (and so their rates)
    start no earlier than the sensor's first event.
    """
    w = await _Window.of(honeypot_id, days)
    start, end = w.start, w.end

    def distinct(precision: int | None = None) -> dict:
        extra = {"precision_threshold": precision} if precision else {}
        return {
            "sessions": {"cardinality": {"field": "session.id", **extra}},
            "sources": {"cardinality": {"field": "source.ip", **extra}},
        }

    aggregations = await w.search(
        honeypot_id,
        {
            "per_day": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1d",
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": int(start.timestamp() * 1000),
                        "max": int(end.timestamp() * 1000),
                    },
                },
                "aggs": distinct(),
            },
            "top_sources": {
                "terms": {"field": "source.ip", "size": 10},
                "aggs": {"country": {"terms": {"field": "source.country", "size": 1}}},
            },
            "protocols": {"terms": {"field": "network.protocol", "size": 10}},
            # few buckets, so the memory is small
            "by_period": w.by_period(distinct(10000)),
        },
    )
    if aggregations is None:
        return None
    window = aggregations["window"]
    spans, skip = w.clip(aggregations)
    # The window's leading periods that end before the first event come first and are dropped.
    buckets = window["by_period"]["buckets"][skip:]
    traffic = []
    for span, bucket in zip(spans, buckets, strict=True):
        events, sessions, sources = (
            bucket["doc_count"],
            bucket["sessions"]["value"],
            bucket["sources"]["value"],
        )
        traffic.append(
            PeriodTraffic(
                period=span,
                events=events,
                sessions=sessions,
                sources=sources,
                events_per_day=_per_day(events, span),
                sessions_per_day=_per_day(sessions, span),
                sources_per_day=_per_day(sources, span),
            )
        )
    return SensorTraffic(
        days=days,
        per_day=[
            DayPoint(
                day=_parse(b["key_as_string"]).date(),
                events=b["doc_count"],
                sessions=b["sessions"]["value"],
                sources=b["sources"]["value"],
            )
            for b in window["per_day"]["buckets"]
        ],
        top_sources=[
            SourceOut(
                ip=b["key"],
                country=b["country"]["buckets"][0]["key"] if b["country"]["buckets"] else None,
                events=b["doc_count"],
            )
            for b in window["top_sources"]["buckets"]
        ],
        protocols={b["key"]: b["doc_count"] for b in window["protocols"]["buckets"]},
        periods=traffic,
    )


_COMMAND_FIELD = "process.command_line.keyword"
_MAX_COMMANDS = 10_000  # distinct commands considered; the rest are reported as truncated
# ES's search.max_buckets (65,536 by default) counts sub-aggregation buckets too: each command
# bucket carries one bucket per period, so the command cap shrinks as periods are added.
_MAX_BUCKETS = 60_000
# Terms per clause. Equal to _MAX_COMMANDS today, so the chunking only guards the constants
# (or the period-derived cap) diverging; it keeps one clause from tripping ES's terms limit.
_TERMS_CHUNK = 10_000


def _technique_commands(commands: list[dict]) -> dict[str, tuple[rules.Rule, list[dict]]]:
    """Group command buckets by the rule they match; one command may match several rules."""
    by_key = {b["key"]: b for b in commands}
    hits, _ = rules.apply_rules(
        [CompactedCommand(event_id="", timestamp="", command=key) for key in by_key]
    )
    grouped: dict[str, tuple[rules.Rule, list[dict]]] = {}
    for hit in hits:
        grouped.setdefault(hit.rule.id, (hit.rule, []))[1].append(by_key[hit.command])
    return grouped


async def get_techniques(honeypot_id: str, days: int) -> SensorTechniques | None:
    """ATT&CK techniques the rulebook finds in every distinct command of the last `days`.

    Not limited to analysed sessions: each distinct command line is matched once and
    counted by its occurrences. None only when the sensor has no events at all.
    """
    w = await _Window.of(honeypot_id, days)
    command_events = {"term": {"event.action": "cowrie.command.input"}}
    # w.spans is the number of range buckets under every command bucket (clipping happens after).
    cap = min(_MAX_COMMANDS, _MAX_BUCKETS // (1 + len(w.spans)))
    aggregations = await w.search(
        honeypot_id,
        {
            "commands": {
                "terms": {"field": _COMMAND_FIELD, "size": cap},
                "aggs": {
                    "first": {"min": {"field": "@timestamp"}},
                    "last": {"max": {"field": "@timestamp"}},
                    "by_period": w.by_period({}),
                },
            }
        },
        command_events,
    )
    if aggregations is None:
        return None
    spans, skip = w.clip(aggregations)
    commands = aggregations["window"]["commands"]
    grouped = _technique_commands(commands["buckets"])
    sessions = {}
    if grouped:
        keys = {name: [b["key"] for b in buckets] for name, (_, buckets) in grouped.items()}
        found = await get_es().search(
            index=get_settings().es_index,
            query=w.filter({"term": {"honeypot.id": honeypot_id}}, command_events),
            size=0,
            aggs={
                "techniques": {
                    "filters": {
                        "filters": {
                            name: {
                                "bool": {
                                    "should": [
                                        {"terms": {_COMMAND_FIELD: terms[i : i + _TERMS_CHUNK]}}
                                        for i in range(0, len(terms), _TERMS_CHUNK)
                                    ],
                                    "minimum_should_match": 1,
                                }
                            }
                            for name, terms in keys.items()
                        }
                    },
                    "aggs": {
                        "sessions": {
                            "cardinality": {"field": "session.id", "precision_threshold": 10000}
                        }
                    },
                }
            },
        )
        sessions = {
            name: b["sessions"]["value"]
            for name, b in found["aggregations"]["techniques"]["buckets"].items()
        }
    techniques = []
    for name, (rule, buckets) in grouped.items():
        per_command = [[p["doc_count"] for p in b["by_period"]["buckets"][skip:]] for b in buckets]
        per_period = [sum(counts) for counts in zip(*per_command, strict=True)]
        techniques.append(
            TechniqueOut(
                technique_id=rule.id,
                name=rule.name,
                tactic=rule.tactic,
                rule_id=rule.id,
                events=sum(b["doc_count"] for b in buckets),
                sessions=sessions[name],
                first_seen=_parse(min(b["first"]["value_as_string"] for b in buckets)),
                last_seen=_parse(max(b["last"]["value_as_string"] for b in buckets)),
                per_period=per_period,
            )
        )
    return SensorTechniques(
        days=days,
        commands_considered=len(commands["buckets"]),
        truncated=commands["sum_other_doc_count"] > 0,
        periods=spans,
        techniques=sorted(techniques, key=lambda t: -t.events),
    )
