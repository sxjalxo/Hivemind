import logging
import re
from dataclasses import dataclass

from elasticsearch import ApiError
from sqlalchemy import select

from app.config import get_settings
from app.db.models import Analysis, TechniqueMapping
from app.db.session import get_session_factory
from app.es.client import get_es
from app.models.intel import AttackerProfileOut, DownloadedFile, SimilarAttacker
from app.services.intel import list_indicators
from app.services.session_builder import get_session_events, list_sessions

logger = logging.getLogger(__name__)


# Literals that differ between runs of the same campaign. An IPv4 address is
# the C2 host of the moment; a hex digest is the build of the moment. Neither
# says anything about what the attacker did.
_VOLATILE_LITERALS = (
    (re.compile(r"\b[0-9a-fA-F]{32,64}\b"), "<hash>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
)


def normalize_command(command: str) -> str:
    """Canonicalise a command line for similarity comparison.

    Case and whitespace are flattened, and the literals that vary between runs
    of one campaign are replaced by placeholders. Two dropper runs pointed at
    different C2 addresses then share a set member, which is the whole point:
    comparing raw strings scored them 0 similar.

    Arguments are deliberately NOT stripped. `cat /etc/passwd` and
    `cat /tmp/notes` map to different ATT&CK techniques, and `chmod 777` is
    not `chmod 644` — collapsing those would trade a false negative for a
    false positive, which is the worse direction for this system.
    """
    text = command
    for pattern, placeholder in _VOLATILE_LITERALS:
        text = pattern.sub(placeholder, text)
    return " ".join(text.lower().split())


def jaccard(a: set[str], b: set[str]) -> float:
    """Set similarity. Deterministic and explainable — no embeddings."""
    union = a | b
    if not union:
        return 0.0
    return round(len(a & b) / len(union), 3)


@dataclass(frozen=True)
class _CommandSet:
    """One attacker's normalised command set, and whether it is all of them."""

    commands: set[str]
    complete: bool


async def _commands_by_ip() -> tuple[dict[str, _CommandSet], str | None]:
    """Distinct commands per attacker IP, in a single aggregation.

    This used to walk every session and fetch its events one request at a
    time -- O(sessions) round trips per profile view. One terms aggregation
    replaces all of it, but a terms aggregation silently drops buckets beyond
    `size`, so each set carries whether it is complete. The second return
    value is the reason similarity cannot be trusted, or None when it can.

    The two caps multiply: 500 IPs x 2000 commands is a million buckets
    against Elasticsearch's default `search.max_buckets` of 65,536, which is
    enforced across the whole aggregation tree. A busy honeypot therefore
    fails the search outright rather than returning a truncated answer, so
    that failure is caught and reported as its own incomplete state instead of
    propagating as a 500 from every attacker profile.
    """
    settings = get_settings()
    command_limit = settings.attacker_command_cardinality_limit
    ip_limit = settings.attacker_ip_cardinality_limit

    try:
        result = await _run_command_aggregation(settings, ip_limit, command_limit)
    except ApiError as exc:
        # too_many_buckets_exception is the expected one; any aggregation
        # failure leaves us unable to compare, which is a reportable state
        # rather than a crash.
        logger.warning("attacker command aggregation failed, similarity withheld: %s", exc)
        return {}, "aggregation_failed"

    ips_agg = result["aggregations"]["ips"]
    every_attacker_present = ips_agg.get("sum_other_doc_count", 0) == 0

    by_ip: dict[str, _CommandSet] = {}
    for bucket in ips_agg["buckets"]:
        command_buckets = bucket["commands"]["buckets"]
        # Three independent truncation signals, because none alone is
        # sufficient. sum_other_doc_count is exact but only non-zero once a
        # bucket was actually dropped; the returned bucket count catches a set
        # that exactly fills the cap (treated as suspect on purpose -- erring
        # toward "incomplete" is the safe direction); the cardinality is
        # approximate at high values but independent of the terms agg.
        truncated = (
            bucket["commands"].get("sum_other_doc_count", 0) > 0
            or len(command_buckets) >= command_limit
            or bucket["distinct_commands"]["value"] > command_limit
        )
        by_ip[bucket["key"]] = _CommandSet(
            commands={normalize_command(b["key"]) for b in command_buckets},
            complete=not truncated,
        )

    if any(not command_set.complete for command_set in by_ip.values()):
        return by_ip, "command_cardinality_limit"
    if not every_attacker_present:
        return by_ip, "attacker_cardinality_limit"
    return by_ip, None


async def _run_command_aggregation(settings, ip_limit: int, command_limit: int) -> dict:
    return await get_es().search(
        index=settings.es_index,
        size=0,
        query={"exists": {"field": "process.command_line"}},
        aggs={
            "ips": {
                "terms": {"field": "source.ip", "size": ip_limit},
                "aggs": {
                    "commands": {
                        "terms": {
                            "field": "process.command_line.keyword",
                            "size": command_limit,
                        }
                    },
                    "distinct_commands": {
                        "cardinality": {"field": "process.command_line.keyword"}
                    },
                },
            }
        },
    )


async def build_profile(ip: str) -> AttackerProfileOut | None:
    sessions = [s for s in await list_sessions() if s.attacker_ip == ip]
    if not sessions:
        return None

    commands: list[str] = []
    honeypots: list[str] = []
    downloaded_files: list[DownloadedFile] = []
    for session in sessions:
        if session.honeypot_name not in honeypots:
            honeypots.append(session.honeypot_name)
        for event in await get_session_events(session.id):
            if event.process and event.process.command_line:
                commands.append(event.process.command_line)
            elif event.event.action == "cowrie.session.file_download" and event.file:
                # Cowrie's raw `size` field is stripped as known-noise by the
                # ingest pipeline (infra/elasticsearch/pipelines/cowrie-ecs.json)
                # -- there is no real size to report here, so it is left
                # unset (never recorded) rather than presented as an
                # observed 0.
                downloaded_files.append(
                    DownloadedFile(
                        name=event.file.name or "unknown",
                        sha256=event.file.hash.sha256 if event.file.hash else "",
                    )
                )

    session_ids = [s.id for s in sessions]
    async with get_session_factory()() as db:
        analyses = (
            (await db.execute(select(Analysis).where(Analysis.session_id.in_(session_ids))))
            .scalars()
            .all()
        )
        technique_ids: list[str] = []
        for analysis in analyses:
            mappings = (
                (
                    await db.execute(
                        select(TechniqueMapping).where(
                            TechniqueMapping.analysis_id == analysis.id
                        )
                    )
                )
                .scalars()
                .all()
            )
            for mapping in mappings:
                if mapping.technique_id not in technique_ids:
                    technique_ids.append(mapping.technique_id)

    risk_score = max((a.risk_score for a in analyses), default=0)
    risk = next((a.risk for a in analyses if a.risk_score == risk_score), "informational")
    behavior = next((a.classification for a in analyses), "Not yet analyzed")

    all_commands, similarity_incomplete_reason = await _commands_by_ip()
    # An attacker with sessions but no commands has an empty set, which is a
    # complete answer, not a truncated one.
    mine = all_commands.get(ip, _CommandSet(commands=set(), complete=True))
    others = {other: theirs for other, theirs in all_commands.items() if other != ip}

    similarity: list[SimilarAttacker] = []
    similarity_complete = similarity_incomplete_reason is None
    similarity_total = 0

    if not similarity_complete:
        # Any truncation, on either side, makes every score involving it
        # wrong, and a failed aggregation gives us nothing to compare at all.
        # Withhold all of them: "similarity unavailable because this profile
        # exceeded the analysis limit" is a true statement, and a plausible
        # 0.87 computed from a subset is not.
        pass
    else:
        scored = ((other, jaccard(mine.commands, theirs.commands)) for other, theirs in others.items())
        similarity = [
            SimilarAttacker(ip=other, score=score) for other, score in scored if score > 0
        ]
        similarity.sort(key=lambda s: s.score, reverse=True)
        similarity_total = len(similarity)

    # Every indicator linked to any of this attacker's own sessions --
    # a full scan of list_indicators(), filtered in Python. Same
    # straightforward-over-optimized approach as _commands_by_ip above; fine
    # at seed-corpus scale, would need indexing (e.g. a session_id-scoped
    # query) at real indicator-table volume.
    session_id_set = set(session_ids)
    indicator_ids = [
        indicator.id
        for indicator in await list_indicators()
        if session_id_set & set(indicator.session_ids)
    ]

    ordered = sorted(sessions, key=lambda s: s.started_at)
    return AttackerProfileOut(
        ip=ip,
        risk=risk,
        risk_score=risk_score,
        behavior_label=behavior,
        sessions=len(sessions),
        first_seen=ordered[0].started_at,
        last_seen=ordered[-1].ended_at or ordered[-1].started_at,
        targeted_honeypots=honeypots,
        commands=commands,
        technique_ids=technique_ids,
        downloaded_files=downloaded_files,
        indicator_ids=indicator_ids,
        geo=None,
        similarity=similarity[:5],
        similarity_total=similarity_total,
        similarity_complete=similarity_complete,
        similarity_incomplete_reason=similarity_incomplete_reason,
        attack_pattern=commands[:12],
    )
