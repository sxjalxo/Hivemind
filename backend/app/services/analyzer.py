import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.db.models import (
    Analysis,
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
    SessionAnalysis,
    SeverityEvidence,
    TechniqueMappingOut,
)
from app.services.compaction import CompactedSession, chunk_session, compact, render_untrusted_block
from app.services.enrichment import write_back_enrichment
from app.services.llm import get_evaluator_client, get_local_client
from app.services.llm.base import LLMClient, LLMValidationError
from app.services.llm.schemas import (
    BehaviorAnalysis,
    ClassificationResult,
    EvidenceCitation,
    Recommendations,
)
from app.services.mitre.mapper import MappingResult, map_techniques
from app.services.persistence import Claim, persist_analysis
from app.services.session_builder import get_session_events
from app.workers.queue import get_queue

logger = logging.getLogger(__name__)

_PROMPTS = Path(__file__).parent / "llm" / "prompts"
PROMPT_VERSION = "v1"


def _prompt(name: str) -> str:
    return (_PROMPTS / name).read_text(encoding="utf-8")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


async def _emit(session_id: str, stage_index: int, **metrics: int) -> None:
    await get_queue().publish(
        session_id,
        AnalysisProgressEvent(
            stage_index=stage_index,
            stage=ANALYSIS_STAGES[stage_index],
            metrics=LiveAnalysisMetrics(
                progress_pct=int((stage_index + 1) / len(ANALYSIS_STAGES) * 100),
                **metrics,
            ),
        ),
    )


async def run_analysis(session_id: str) -> uuid.UUID:
    """Run the seven-stage pipeline for one session.

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
    evaluator, tier = get_evaluator_client()
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

    # Stage 5 — intel correlation is filled in by Task 15; emit the stage now
    # so the UI stepper advances truthfully rather than stalling. No
    # correlation result is fabricated here.
    await _emit(session_id, 5, techniques_detected=len(mapping.techniques))

    # Stage 6 — recommendations (own context per chunk, cloud evaluator when configured)
    actions = await _recommend(evaluator, chunks, classification, mapping)
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
        evaluator_model=evaluator.model_name if tier == "cloud" else None,
        prompt_version=PROMPT_VERSION,
    )

    await persist_analysis(
        analysis, claims, actions, session_id, event_timestamps, prior_rejected=rejected
    )

    # Denormalized projection onto Elasticsearch, written only after the
    # Postgres write (the system of record) has succeeded. See
    # app.services.enrichment for why mitre.* is restricted to rule-backed
    # mappings.
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
    prompt = (
        _prompt("recommend.md")
        .replace("{untrusted_block}", block)
        .replace("{classification}", classification)
        .replace("{techniques}", technique_list)
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
    async def refs_for(parent_type: ParentType, parent_id) -> list[EvidenceRef]:  # noqa: ANN001
        return (
            (
                await db.execute(
                    select(EvidenceRef).where(
                        EvidenceRef.parent_type == parent_type,
                        EvidenceRef.parent_id == parent_id,
                    )
                )
            )
            .scalars()
            .all()
        )

    mappings = (
        (await db.execute(select(TechniqueMapping).where(TechniqueMapping.analysis_id == analysis.id)))
        .scalars()
        .all()
    )
    behaviors = (
        (await db.execute(select(ObservedBehavior).where(ObservedBehavior.analysis_id == analysis.id)))
        .scalars()
        .all()
    )
    suspicious = (
        (await db.execute(select(SuspiciousIndicator).where(SuspiciousIndicator.analysis_id == analysis.id)))
        .scalars()
        .all()
    )
    actions = (
        (await db.execute(select(RecommendedAction).where(RecommendedAction.analysis_id == analysis.id)))
        .scalars()
        .all()
    )

    techniques = []
    for mapping in mappings:
        refs = await refs_for(ParentType.TECHNIQUE_MAPPING, mapping.id)
        techniques.append(
            TechniqueMappingOut(
                technique_id=mapping.technique_id,
                technique_name=mapping.technique_name,
                tactic=mapping.tactic,
                confidence=mapping.confidence,
                evidence=_refs_to_out(refs),
                related_commands=[r.artifact for r in refs],
                ai_explanation=mapping.ai_explanation,
                timestamp=mapping.timestamp.isoformat().replace("+00:00", "Z"),
            )
        )

    return SessionAnalysis(
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
        observed_behavior=[
            LabelledEvidence(
                label=b.label,
                evidence=_refs_to_out(await refs_for(ParentType.OBSERVED_BEHAVIOR, b.id)),
            )
            for b in behaviors
        ],
        suspicious_indicators=[
            SeverityEvidence(
                label=s.label,
                severity=s.severity,
                evidence=_refs_to_out(await refs_for(ParentType.SUSPICIOUS_INDICATOR, s.id)),
            )
            for s in suspicious
        ],
        recommended_actions=[
            RecommendedActionOut(priority=a.priority, action=a.action, rationale=a.rationale)
            for a in actions
        ],
        techniques=techniques,
    )


async def load_analysis(analysis_id: uuid.UUID) -> SessionAnalysis | None:
    async with get_session_factory()() as db:
        analysis = await db.get(Analysis, analysis_id)
        return await _hydrate(db, analysis) if analysis else None


async def load_history() -> list[SessionAnalysis]:
    async with get_session_factory()() as db:
        rows = (
            (await db.execute(select(Analysis).order_by(Analysis.created_at.desc())))
            .scalars()
            .all()
        )
        return [await _hydrate(db, row) for row in rows]


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
