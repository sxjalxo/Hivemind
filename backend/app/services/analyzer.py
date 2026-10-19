import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.auth import Actor
from app.db.models import (
    Analysis,
    ClaimRejection,
    EvidenceRef,
    ObservedBehavior,
    ParentType,
    RecommendedAction,
    SuspiciousIndicator,
    TechniqueMapping,
)
from app.db.session import get_session_factory
from app.models.analysis import (
    ANALYSIS_STAGES,
    AnalysisProgressEvent,
    EvidenceRefOut,
    LabelledEvidence,
    LiveAnalysisMetrics,
    RecommendedActionOut,
    RejectedClaimOut,
    SessionAnalysis,
    SeverityEvidence,
    TechniqueMappingOut,
)
from app.services.chunking import flatten
from app.services.compaction import CompactedSession, chunk_session, compact, render_untrusted_block
from app.services.enrichment import write_back_enrichment
from app.services.llm import get_local_client, get_recommendation_client
from app.services.llm.base import LLMClient, LLMValidationError
from app.services.llm.schemas import (
    BehaviorAnalysis,
    ClassificationResult,
    EvidenceCitation,
    Recommendations,
)
from app.services.mitre.mapper import MappingResult, map_techniques
from app.services.persistence import Claim, persist_analysis
from app.services.session_builder import get_session_events, honeypots_for_sessions
from app.workers.queue import analysis_job_key, get_queue

logger = logging.getLogger(__name__)

_PROMPTS = Path(__file__).parent / "llm" / "prompts"
PROMPT_VERSION = "v2"  # v2 (2026-10-19): classification is a closed vocabulary


def _prompt(name: str) -> str:
    return (_PROMPTS / name).read_text(encoding="utf-8")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


async def _emit(session_id: str, stage_index: int, **metrics: int) -> None:
    await get_queue().publish(
        analysis_job_key(session_id),
        AnalysisProgressEvent(
            stage_index=stage_index,
            stage=ANALYSIS_STAGES[stage_index],
            metrics=LiveAnalysisMetrics(
                progress_pct=int((stage_index + 1) / len(ANALYSIS_STAGES) * 100),
                **metrics,
            ),
        ),
    )


async def run_analysis(session_id: str, actor: Actor | None = None) -> uuid.UUID:
    """Run the seven-stage pipeline for one session.

    `actor` records who asked for it -- one LLM pipeline on the one GPU,
    writing claims the interface presents as findings. Omitting it stores
    `unrecorded`, the value reserved for rows that predate the audit trail,
    so every real caller passes one. See `app.auth.Actor`.

    Each LLM stage gets its own context and its own prompt -- the paper
    found that merging categories into a single prompt produces shallower
    output. A session whose rendered block would exceed the model's
    context window is chunked first (see `app.services.compaction.
    chunk_session` and `app.services.chunking`); each chunk still gets its
    own, independent call per stage, and per-stage results are merged
    afterward. That keeps "one context per stage" true even for an
    oversized session, instead of silently letting Ollama truncate an
    over-budget prompt on its own.
    """
    started = time.monotonic()
    events = await get_session_events(session_id)
    if not events:
        raise ValueError(f"unknown session {session_id}")

    await _emit(session_id, 0, events_processed=len(events))

    compacted = compact(events)
    chunks = chunk_session(compacted)
    event_timestamps = {e.id: _parse(e.timestamp) for e in events}
    await _emit(
        session_id, 1, events_processed=len(events), commands_analyzed=len(compacted.commands)
    )

    local = get_local_client()
    # The recommendation stage's client, NOT the realism evaluator -- see
    # `llm.get_recommendation_client` for why the distinction has teeth.
    recommender, tier = get_recommendation_client()
    claims: list[Claim] = []
    rejected = 0

    # Stage 2 — classification (own context per chunk, merged afterward)
    classification = await _classify(local, chunks)
    await _emit(session_id, 2, commands_analyzed=len(compacted.commands))

    # Stage 3 — observed behaviors and suspicious indicators (own context per chunk)
    behaviors, behavior_rejects = await _behaviors(local, chunks)
    rejected += behavior_rejects
    claims.extend(behaviors)
    await _emit(session_id, 3, iocs_extracted=len(behaviors))

    # Stage 4 — ATT&CK mapping. Deterministic rules run over the FULL,
    # untruncated command list (cheap, no context-window concern); the LLM
    # gap-fill for whatever rules miss is chunked internally by
    # map_techniques when the unmatched list itself would overflow.
    mapping = await map_techniques(compacted.commands, local)
    rejected += mapping.rejected
    for technique in mapping.techniques:
        claims.append(
            Claim(
                kind=ParentType.TECHNIQUE_MAPPING,
                payload={
                    "technique_id": technique.technique_id,
                    "technique_name": technique.technique_name,
                    "tactic": technique.tactic,
                    "confidence": technique.confidence,
                    "ai_explanation": technique.ai_explanation,
                    "source": technique.source,
                    "rule_id": technique.rule_id,
                    "timestamp": datetime.now(timezone.utc),
                },
                evidence=technique.evidence,
            )
        )
    await _emit(session_id, 4, techniques_detected=len(mapping.techniques))

    # Stage 5 — correlate IOCs across sessions
    from app.services.intel import correlate, extract_indicators

    extracted = extract_indicators(compacted)
    await correlate(session_id, extracted)
    await _emit(
        session_id,
        5,
        techniques_detected=len(mapping.techniques),
        iocs_extracted=len(extracted),
    )

    # Stage 6 — recommendations (own context per chunk, cloud model when configured)
    actions = await _recommend(recommender, chunks, classification, mapping)
    await _emit(session_id, 6, techniques_detected=len(mapping.techniques))

    analysis = Analysis(
        id=uuid.uuid4(),
        session_id=session_id,
        model=local.model_name,
        analysis_type="session_behavior",
        status="completed",
        created_at=datetime.now(timezone.utc),
        duration_seconds=int(time.monotonic() - started),
        classification=classification.classification,
        confidence=classification.confidence,
        risk_score=classification.risk_score,
        risk=classification.risk,
        behavior_summary=classification.behavior_summary,
        model_tier=tier,
        # The COLUMN is named evaluator_model; it records which cloud model
        # produced this analysis's recommendations. Renaming the column is a
        # migration, and the stored values are correct either way.
        evaluator_model=recommender.model_name if tier == "cloud" else None,
        prompt_version=PROMPT_VERSION,
        started_by=(actor or Actor.unrecorded()).key,
        started_by_label=(actor or Actor.unrecorded()).label,
    )

    await persist_analysis(
        analysis,
        claims,
        actions,
        session_id,
        event_timestamps,
        prior_rejected=rejected,
        rejections=mapping.rejections,
    )

    # Denormalized projection onto Elasticsearch, written only after the
    # Postgres write (the system of record) has succeeded. Best-effort:
    # write_back_enrichment catches and logs its own failures internally
    # and never raises, so a transient ES error here can never turn an
    # already-completed, already-persisted analysis into a bare 500 -- see
    # app.services.enrichment for why mitre.* is restricted to rule-backed
    # mappings, and how it stays authoritative (not additive) across
    # re-analysis.
    await write_back_enrichment(
        session_id=session_id,
        risk_score=analysis.risk_score,
        risk=analysis.risk,
        classification=analysis.classification,
        techniques=mapping.techniques,
    )

    return analysis.id


def _fallback_citation(compacted: CompactedSession) -> list[EvidenceCitation]:
    """A real citation for the degraded path.

    ClassificationResult requires at least one citation, so even the fallback
    must point at something that exists. The first recorded command is the
    honest choice; a session with no commands cites its connect event.
    """
    if compacted.commands:
        first = compacted.commands[0]
        return [EvidenceCitation(event_id=first.event_id, artifact=first.command)]
    return [
        EvidenceCitation(
            event_id=compacted.first_event_id, artifact="session recorded, no commands"
        )
    ]


async def _classify_one(
    client: LLMClient, block: str, compacted: CompactedSession
) -> ClassificationResult:
    """Classify one chunk's behavior. A model failure degrades to a labelled result."""
    try:
        return await client.complete_json(
            _prompt("classify.md").replace("{untrusted_block}", block),
            ClassificationResult,
        )
    except LLMValidationError as exc:
        logger.warning("classification failed for %s: %s", compacted.session_id, exc)
        return ClassificationResult(
            classification="Unclassified",
            confidence=0.0,
            risk_score=0,
            risk="informational",
            behavior_summary=(
                "The model did not return a usable classification. "
                f"{len(compacted.commands)} commands were recorded."
            ),
            evidence=_fallback_citation(compacted),
        )


def _merge_classifications(results: list[ClassificationResult]) -> ClassificationResult:
    """Merge one classification per chunk into a single session-level verdict.

    Each chunk was analyzed in complete isolation -- the guarantee
    chunk-and-merge exists to provide -- so the merge must not invent
    anything beyond what the individual chunks concluded. The chunk with
    the highest risk_score drives `classification`/`behavior_summary` (a
    defender cares about the worst finding any chunk reached, not an
    average across severities that were never jointly considered).
    `confidence` is the mean across chunks: a crude but honest way to say
    "less certain, because the evidence was split and no single call saw
    it all." `evidence` is the union of every chunk's citations,
    deduplicated.
    """
    if len(results) == 1:
        return results[0]

    worst = max(results, key=lambda r: r.risk_score)
    confidence = sum(r.confidence for r in results) / len(results)

    seen: set[tuple[str, str]] = set()
    evidence: list[EvidenceCitation] = []
    for result in results:
        for citation in result.evidence:
            key = (citation.event_id, citation.artifact)
            if key not in seen:
                seen.add(key)
                evidence.append(citation)

    summaries = list(dict.fromkeys(r.behavior_summary for r in results if r.behavior_summary))
    behavior_summary = " ".join(summaries) or worst.behavior_summary

    return ClassificationResult(
        classification=worst.classification,
        confidence=confidence,
        risk_score=worst.risk_score,
        risk=worst.risk,
        behavior_summary=behavior_summary,
        evidence=evidence,
    )


async def _classify(
    client: LLMClient, chunks: list[CompactedSession]
) -> ClassificationResult:
    results = [
        await _classify_one(client, render_untrusted_block(chunk), chunk) for chunk in chunks
    ]
    return _merge_classifications(results)


async def _behaviors_one(client: LLMClient, block: str) -> list[Claim]:
    try:
        result = await client.complete_json(
            _prompt("behaviors.md").replace("{untrusted_block}", block),
            BehaviorAnalysis,
        )
    except LLMValidationError as exc:
        logger.warning("behaviour stage failed: %s", exc)
        return []

    return [
        Claim(
            kind=ParentType.OBSERVED_BEHAVIOR,
            payload={"label": item.label},
            evidence=item.evidence,
        )
        for item in result.observed
    ] + [
        Claim(
            kind=ParentType.SUSPICIOUS_INDICATOR,
            payload={"label": item.label, "severity": item.severity},
            evidence=item.evidence,
        )
        for item in result.suspicious
    ]


async def _behaviors(
    client: LLMClient, chunks: list[CompactedSession]
) -> tuple[list[Claim], int]:
    """Run the behaviors stage once per chunk and concatenate the results.

    Unlike classification there is nothing to reconcile: each chunk's
    observed/suspicious items describe only the commands in that chunk, so
    merging is simple concatenation. `persist_analysis` still grounds every
    claim independently, so nothing here bypasses the evidence barrier.
    """
    claims: list[Claim] = []
    for chunk in chunks:
        claims.extend(await _behaviors_one(client, render_untrusted_block(chunk)))
    return claims, 0


async def _recommend_one(
    client: LLMClient, block: str, classification: str, technique_list: str
) -> list[dict]:
    # `{untrusted_block}` is substituted LAST, and the order is load-bearing.
    #
    # Substituted first, a command containing the literal string
    # `{classification}` or `{techniques}` was expanded by the passes that
    # followed -- attacker text choosing what else gets spliced into the
    # prompt. `evaluator._render` records the same rule for the same reason.
    #
    # `classification` is flattened as well, and it is the subtler half:
    # unlike the block it lands OUTSIDE the fence, in the prompt's trusted
    # region, and it is not our text -- the local model wrote it after
    # reading this attacker's commands. A newline in it would open a line of
    # its own next to our instructions.
    prompt = (
        _prompt("recommend.md")
        .replace("{classification}", flatten(classification))
        .replace("{techniques}", technique_list)
        .replace("{untrusted_block}", block)
    )
    try:
        result = await client.complete_json(prompt, Recommendations)
    except LLMValidationError as exc:
        logger.warning("recommendation stage failed: %s", exc)
        return []
    return [
        {"priority": a.priority, "action": a.action, "rationale": a.rationale}
        for a in result.actions
    ]


async def _recommend(
    client: LLMClient,
    chunks: list[CompactedSession],
    classification: ClassificationResult,
    mapping: MappingResult,
) -> list[dict]:
    technique_list = (
        ", ".join(f"{t.technique_id} ({t.technique_name})" for t in mapping.techniques)
        or "none mapped"
    )

    actions: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for chunk in chunks:
        block = render_untrusted_block(chunk)
        for action in await _recommend_one(
            client, block, classification.classification, technique_list
        ):
            key = (action["priority"], action["action"])
            if key not in seen:
                seen.add(key)
                actions.append(action)
    return actions


def _refs_to_out(refs: list[EvidenceRef]) -> list[EvidenceRefOut]:
    return [
        EvidenceRefOut(
            artifact=r.artifact,
            session_id=r.session_id,
            timestamp=r.timestamp.isoformat().replace("+00:00", "Z"),
            event_id=r.es_event_id,
        )
        for r in refs
    ]


async def _hydrate(db, analysis: Analysis) -> SessionAnalysis:
    return (await _hydrate_many(db, [analysis]))[0]


async def _hydrate_many(db, analyses: list[Analysis]) -> list[SessionAnalysis]:  # noqa: ANN001
    """Every analysis on a page, with its claims and evidence, in seven queries.

    Was one `_hydrate` per row -- five child queries plus one evidence query
    PER CLAIM -- so a page of history cost hundreds of round trips, and twenty
    concurrent requests took ~2.7 s on one worker. The same rows, in the same
    order, now come back in one query per table for the whole page.

    Every query carries an explicit ORDER BY. Without one, Postgres makes no
    ordering guarantee across repeated SELECTs of the same rows (physical
    storage order can shift with vacuum/autoanalyze even when nothing about
    the data itself changed) -- which showed up as `techniques` (and the
    `classificationChain`/`mitreTechniqueIds` derived from it) reordering
    between two back-to-back reads of the same analysis. `id` (a random uuid4)
    is not insertion order, but it IS a fixed, stable sort key. Tables that
    also carry a meaningful timestamp (`TechniqueMapping`, `EvidenceRef`) sort
    by that first, `id` only as the tiebreaker for same-instant rows. Grouping
    by analysis below keeps each analysis's rows in that order.
    """
    if not analyses:
        return []
    ids = [a.id for a in analyses]

    async def rows(model, *order) -> dict:  # noqa: ANN001, ANN002
        grouped: dict = {}
        result = await db.execute(select(model).where(model.analysis_id.in_(ids)).order_by(*order))
        for row in result.scalars().all():
            grouped.setdefault(row.analysis_id, []).append(row)
        return grouped

    mappings = await rows(TechniqueMapping, TechniqueMapping.timestamp, TechniqueMapping.id)
    behaviors = await rows(ObservedBehavior, ObservedBehavior.id)
    suspicious = await rows(SuspiciousIndicator, SuspiciousIndicator.id)
    actions = await rows(RecommendedAction, RecommendedAction.id)
    rejections = await rows(ClaimRejection, ClaimRejection.stage, ClaimRejection.id)

    parent_ids = [
        row.id
        for grouped in (mappings, behaviors, suspicious)
        for group in grouped.values()
        for row in group
    ]
    refs: dict = {}
    if parent_ids:
        result = await db.execute(
            select(EvidenceRef)
            .where(EvidenceRef.parent_id.in_(parent_ids))
            .order_by(EvidenceRef.timestamp, EvidenceRef.id)
        )
        for ref in result.scalars().all():
            refs.setdefault((ref.parent_type, ref.parent_id), []).append(ref)

    def refs_for(parent_type: ParentType, parent_id) -> list[EvidenceRef]:  # noqa: ANN001
        return refs.get((parent_type, parent_id), [])

    out: list[SessionAnalysis] = []
    for analysis in analyses:
        techniques = []
        for mapping in mappings.get(analysis.id, []):
            mapping_refs = refs_for(ParentType.TECHNIQUE_MAPPING, mapping.id)
            techniques.append(
                TechniqueMappingOut(
                    technique_id=mapping.technique_id,
                    technique_name=mapping.technique_name,
                    tactic=mapping.tactic,
                    observed=mapping.source == "rule",
                    confidence=mapping.confidence,
                    evidence=_refs_to_out(mapping_refs),
                    related_commands=[r.artifact for r in mapping_refs],
                    ai_explanation=mapping.ai_explanation,
                    timestamp=mapping.timestamp.isoformat().replace("+00:00", "Z"),
                )
            )

        out.append(
            SessionAnalysis(
                id=str(analysis.id),
                session_id=analysis.session_id,
                model=analysis.model,
                analysis_type=analysis.analysis_type,
                status=analysis.status,
                created_at=analysis.created_at.isoformat().replace("+00:00", "Z"),
                duration_seconds=analysis.duration_seconds,
                classification=analysis.classification,
                confidence=analysis.confidence,
                risk_score=analysis.risk_score,
                risk=analysis.risk,
                behavior_summary=analysis.behavior_summary,
                started_by=analysis.started_by,
                started_by_label=analysis.started_by_label,
                observed_behavior=[
                    LabelledEvidence(
                        label=b.label,
                        evidence=_refs_to_out(refs_for(ParentType.OBSERVED_BEHAVIOR, b.id)),
                    )
                    for b in behaviors.get(analysis.id, [])
                ],
                suspicious_indicators=[
                    SeverityEvidence(
                        label=s.label,
                        severity=s.severity,
                        evidence=_refs_to_out(refs_for(ParentType.SUSPICIOUS_INDICATOR, s.id)),
                    )
                    for s in suspicious.get(analysis.id, [])
                ],
                recommended_actions=[
                    RecommendedActionOut(
                        priority=a.priority, action=a.action, rationale=a.rationale
                    )
                    for a in actions.get(analysis.id, [])
                ],
                techniques=techniques,
                rejected_claims=analysis.rejected_claims,
                rejections=[
                    RejectedClaimOut(
                        stage=r.stage,
                        kind=r.kind,
                        reason=r.reason,
                        technique_id=r.technique_id,
                        text=r.text,
                        cited_event_ids=r.cited_event_ids or [],
                    )
                    for r in rejections.get(analysis.id, [])
                ],
            )
        )
    return out


async def load_analysis(analysis_id: uuid.UUID) -> SessionAnalysis | None:
    async with get_session_factory()() as db:
        analysis = await db.get(Analysis, analysis_id)
        return await _hydrate(db, analysis) if analysis else None


async def load_history(
    limit: int | None = None,
    deny_honeypots: set[str] | None = None,
    offset: int = 0,
) -> list[SessionAnalysis]:
    """Newest analyses first, hydrated. `offset` and `limit` count VISIBLE rows.

    `limit` is None for internal callers and set by the route. Only the
    returned page is hydrated -- the expensive half, since this list grows
    with every analysis ever run.

    A scoped caller's rows are filtered by honeypot, and `analyses` has no
    honeypot column to filter ON (the sensor is a property of the session,
    which lives in Elasticsearch). So rows are read in batches and filtered
    until the page is full, rather than one `limit` of rows filtered after
    the fact: that returned short pages, and a short page cannot be told apart
    from the end of the list. A session whose events have aged out is omitted
    too: an id that cannot be placed on a sensor cannot be shown to a scoped
    caller.
    """
    statement = select(Analysis).order_by(Analysis.created_at.desc(), Analysis.id)
    async with get_session_factory()() as db:
        if not deny_honeypots:
            if limit is not None:
                statement = statement.offset(offset).limit(limit)
            elif offset:
                statement = statement.offset(offset)
            rows = (await db.execute(statement)).scalars().all()
        else:
            rows = await _visible_rows(db, statement, deny_honeypots, offset, limit)
        return await _hydrate_many(db, list(rows))


# How many rows a scoped read fetches per round while filling a page.
_SCOPE_BATCH = 200


async def _visible_rows(
    db, statement, deny_honeypots: set[str], offset: int, limit: int | None
) -> list[Analysis]:
    rows: list[Analysis] = []
    skipped = 0
    read = 0
    while limit is None or len(rows) < limit:
        batch = (
            (await db.execute(statement.offset(read).limit(_SCOPE_BATCH))).scalars().all()
        )
        read += len(batch)
        owners = await honeypots_for_sessions([a.session_id for a in batch])
        for row in batch:
            owner = owners.get(row.session_id)
            if owner is None or owner in deny_honeypots:
                continue
            if skipped < offset:
                skipped += 1
            elif limit is None or len(rows) < limit:
                rows.append(row)
        if len(batch) < _SCOPE_BATCH:
            break
    return rows


async def latest_verdicts(
    session_ids: list[str],
) -> dict[str, tuple[str, int, list[tuple[str, str]]]]:
    """For each session with an analysis: (risk, risk_score, [(technique, tactic)]).

    What a session ROW needs from its latest analysis, for a whole page in two
    queries -- `latest_for_session` hydrates every claim's evidence, which a
    list never shows. Techniques come back in `_hydrate`'s order (timestamp,
    then id), so a row reads the same either way.
    """
    if not session_ids:
        return {}
    async with get_session_factory()() as db:
        latest = (
            (
                await db.execute(
                    select(Analysis)
                    .where(Analysis.session_id.in_(session_ids))
                    .order_by(Analysis.session_id, Analysis.created_at.desc())
                    .distinct(Analysis.session_id)
                )
            )
            .scalars()
            .all()
        )
        if not latest:
            return {}
        mappings = (
            (
                await db.execute(
                    select(TechniqueMapping)
                    .where(TechniqueMapping.analysis_id.in_([a.id for a in latest]))
                    .order_by(
                        TechniqueMapping.analysis_id,
                        TechniqueMapping.timestamp,
                        TechniqueMapping.id,
                    )
                )
            )
            .scalars()
            .all()
        )
    techniques: dict = {}
    for mapping in mappings:
        techniques.setdefault(mapping.analysis_id, []).append(
            (mapping.technique_id, mapping.tactic)
        )
    return {
        a.session_id: (a.risk, a.risk_score, techniques.get(a.id, [])) for a in latest
    }


async def latest_for_session(session_id: str) -> SessionAnalysis | None:
    async with get_session_factory()() as db:
        row = (
            (
                await db.execute(
                    select(Analysis)
                    .where(Analysis.session_id == session_id)
                    .order_by(Analysis.created_at.desc())
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        return await _hydrate(db, row) if row else None
