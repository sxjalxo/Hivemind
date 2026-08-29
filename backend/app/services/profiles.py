from sqlalchemy import select

from app.db.models import Analysis, TechniqueMapping
from app.db.session import get_session_factory
from app.models.intel import AttackerProfileOut, DownloadedFile, SimilarAttacker
from app.services.intel import list_indicators
from app.services.session_builder import get_session_events, list_sessions


def jaccard(a: set[str], b: set[str]) -> float:
    """Set similarity. Deterministic and explainable — no embeddings."""
    union = a | b
    if not union:
        return 0.0
    return round(len(a & b) / len(union), 3)


async def _commands_by_ip() -> dict[str, set[str]]:
    commands: dict[str, set[str]] = {}
    for session in await list_sessions():
        events = await get_session_events(session.id)
        texts = {
            e.process.command_line
            for e in events
            if e.process and e.process.command_line
        }
        commands.setdefault(session.attacker_ip, set()).update(texts)
    return commands


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

    all_commands = await _commands_by_ip()
    mine = all_commands.get(ip, set())
    similarity = [
        SimilarAttacker(ip=other, score=jaccard(mine, theirs))
        for other, theirs in all_commands.items()
        if other != ip and jaccard(mine, theirs) > 0
    ]
    similarity.sort(key=lambda s: s.score, reverse=True)

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
        attack_pattern=commands[:12],
    )
