"""Reading evaluation runs back: hydration and the list/detail endpoints.

Extracted from `runs.py`, which had grown to hold orchestration, persistence,
hydration, lifecycle and comparison at once. This half never writes: it turns
stored rows into the shapes the API returns, and the distinction is worth a
file boundary because the two halves fail differently. An orchestration bug
corrupts a run; a bug here misreports one that is fine.

The asymmetry between the two endpoints is the thing to preserve. A summary
is cheap and a detail is ~7 queries per run, so a list of details would
transfer the whole evaluation database to draw a table. `list_run_summaries`
exists for that reason and must not quietly grow the detail's fields.
"""

import uuid

from sqlalchemy import select

from app.db.models import (
    EvaluationCategoryScore,
    EvaluationChainStep,
    EvaluationEvidence,
    EvaluationFinding,
    EvaluationModuleResult,
    EvaluationProbeResult,
    EvaluationRun,
    RunStatus,
)
from app.db.session import get_session_factory
from app.models.evaluation import (
    CategoryScoreOut,
    ChainStepOut,
    EvaluationRunOut,
    EvaluationRunSummary,
    EvidenceOut,
    FindingOut,
    ModuleResultOut,
    ProbeResultOut,
)
from app.services.evaluation.state import iso as _iso


def _to_out(
    run: EvaluationRun,
    scores: list[EvaluationCategoryScore],
    modules: list[EvaluationModuleResult],
    findings: list[EvaluationFinding],
    evidence_by_finding: dict[uuid.UUID, list[EvaluationEvidence]],
    chain_steps: list[EvaluationChainStep],
    probe_rows: list[EvaluationProbeResult],
) -> EvaluationRunOut:
    return EvaluationRunOut(
        id=str(run.id),
        honeypot_id=run.honeypot_id,
        status=run.status,
        started_at=_iso(run.started_at),
        finished_at=_iso(run.finished_at) if run.finished_at else None,
        agent_model=run.agent_model,
        evaluator_model=run.evaluator_model,
        evaluator_status=run.evaluator_status,
        honeypot_fingerprint=run.honeypot_fingerprint,
        evaluation_config_fingerprint=run.evaluation_config_fingerprint,
        started_by=run.started_by,
        started_by_label=run.started_by_label,
        category_scores=[
            CategoryScoreOut(
                characteristic=score.characteristic,
                deterministic_score=score.deterministic_score,
                evaluator_rating=score.evaluator_rating,
            )
            for score in scores
        ],
        modules=[
            ModuleResultOut(
                module=module.module, module_status=module.module_status, detail=module.detail
            )
            for module in modules
        ],
        findings=[
            FindingOut(
                id=str(finding.id),
                characteristic=finding.characteristic,
                severity=finding.severity,
                finding=finding.finding,
                recommendation=finding.recommendation,
                source=finding.source,
                finding_key=finding.finding_key,
                evidence=[
                    EvidenceOut(
                        kind=item.kind,
                        es_event_id=item.es_event_id,
                        chain_step_id=str(item.chain_step_id) if item.chain_step_id else None,
                        probe_result_id=(
                            str(item.probe_result_id) if item.probe_result_id else None
                        ),
                    )
                    for item in evidence_by_finding.get(finding.id, [])
                ],
            )
            for finding in findings
        ],
        chain_steps=[
            ChainStepOut(
                id=str(step.id),
                chain_id=step.chain_id,
                step_index=step.step_index,
                command=step.command,
                cowrie_event_id=step.cowrie_event_id,
                matched_rule_id=step.matched_rule_id,
                expected_technique_id=step.expected_technique_id,
                fact_status=step.fact_status,
            )
            for step in chain_steps
        ],
        probe_results=[
            ProbeResultOut(
                id=str(row.id),
                module=row.module,
                probe_id=row.probe_id,
                target=row.target,
                establishes=row.establishes,
                value=row.value,
                fact_status=row.fact_status,
            )
            for row in probe_rows
        ],
    )


async def _hydrate(db, run: EvaluationRun) -> EvaluationRunOut:
    # Every query carries an explicit ORDER BY: without one Postgres makes no
    # ordering guarantee across repeated SELECTs of the same rows, which shows
    # up as lists reshuffling between two reads of the same run. See the same
    # note in `app.services.analyzer._hydrate`.
    async def rows(model, order):
        return (
            (await db.execute(select(model).where(model.run_id == run.id).order_by(*order)))
            .scalars()
            .all()
        )

    scores = await rows(EvaluationCategoryScore, (EvaluationCategoryScore.characteristic,))
    modules = await rows(
        EvaluationModuleResult, (EvaluationModuleResult.started_at, EvaluationModuleResult.id)
    )
    findings = await rows(
        EvaluationFinding, (EvaluationFinding.characteristic, EvaluationFinding.id)
    )
    chain_steps = await rows(
        EvaluationChainStep,
        (EvaluationChainStep.chain_id, EvaluationChainStep.step_index, EvaluationChainStep.id),
    )
    probe_rows = await rows(
        EvaluationProbeResult, (EvaluationProbeResult.module, EvaluationProbeResult.probe_id)
    )

    evidence_by_finding: dict[uuid.UUID, list[EvaluationEvidence]] = {}
    if findings:
        evidence = (
            (
                await db.execute(
                    select(EvaluationEvidence)
                    .where(EvaluationEvidence.finding_id.in_([f.id for f in findings]))
                    .order_by(EvaluationEvidence.id)
                )
            )
            .scalars()
            .all()
        )
        for item in evidence:
            evidence_by_finding.setdefault(item.finding_id, []).append(item)

    return _to_out(
        run, scores, modules, findings, evidence_by_finding, chain_steps, probe_rows
    )


async def load_run(run_id: uuid.UUID) -> EvaluationRunOut | None:
    async with get_session_factory()() as db:
        run = await db.get(EvaluationRun, run_id)
        return await _hydrate(db, run) if run else None


async def list_runs() -> list[EvaluationRunOut]:
    async with get_session_factory()() as db:
        runs = (
            (
                await db.execute(
                    select(EvaluationRun).order_by(
                        EvaluationRun.started_at.desc(), EvaluationRun.id
                    )
                )
            )
            .scalars()
            .all()
        )
        return [await _hydrate(db, run) for run in runs]


def _to_summary(
    run: EvaluationRun, scores: list[EvaluationCategoryScore]
) -> EvaluationRunSummary:
    return EvaluationRunSummary(
        id=str(run.id),
        honeypot_id=run.honeypot_id,
        status=run.status,
        started_at=_iso(run.started_at),
        finished_at=_iso(run.finished_at) if run.finished_at else None,
        agent_model=run.agent_model,
        evaluator_model=run.evaluator_model,
        evaluator_status=run.evaluator_status,
        honeypot_fingerprint=run.honeypot_fingerprint,
        evaluation_config_fingerprint=run.evaluation_config_fingerprint,
        started_by=run.started_by,
        started_by_label=run.started_by_label,
        category_scores=[
            CategoryScoreOut(
                characteristic=score.characteristic,
                # Carried as stored. None means "not established" and is
                # never coerced to 0, and the two scores stay separate.
                deterministic_score=score.deterministic_score,
                evaluator_rating=score.evaluator_rating,
            )
            for score in scores
        ],
    )


async def list_run_summaries(limit: int) -> list[EvaluationRunSummary]:
    """History rows, bounded, without the per-run hydration.

    `list_runs` calls `_hydrate` per run: every probe result, finding,
    evidence row and chain step, at ~7 queries each. A history page needs
    only what renders a row and a trend, so this is two queries in total
    however many runs are returned, and `limit` bounds the number of rows.
    Full hydration stays on `load_run` -- this is an addition, not a
    replacement.
    """
    async with get_session_factory()() as db:
        rows = (
            (
                await db.execute(
                    select(EvaluationRun)
                    .order_by(EvaluationRun.started_at.desc(), EvaluationRun.id)
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            return []
        # Explicit ORDER BY for the same reason `_hydrate` gives: without one
        # Postgres makes no ordering guarantee, and the scores would reshuffle
        # between two reads of the same run.
        scores = (
            (
                await db.execute(
                    select(EvaluationCategoryScore)
                    .where(EvaluationCategoryScore.run_id.in_([row.id for row in rows]))
                    .order_by(
                        EvaluationCategoryScore.run_id, EvaluationCategoryScore.characteristic
                    )
                )
            )
            .scalars()
            .all()
        )

    by_run: dict[uuid.UUID, list[EvaluationCategoryScore]] = {}
    for score in scores:
        by_run.setdefault(score.run_id, []).append(score)
    return [_to_summary(row, by_run.get(row.id, [])) for row in rows]


async def is_running(honeypot_id: str) -> bool:
    """One run at a time per honeypot (spec §6.2; Task 15 returns 409).

    Concurrent runs interleave their traffic, which makes tcpdump attribution
    and the chain read-back's time window meaningless.

    This is a plain read and enforces nothing on its own. Two callers can both
    see False and both insert, and there is no partial unique index on
    `(honeypot_id) WHERE status = 'running'` to stop them -- closing that
    TOCTOU is Task 15's job at the API layer, and it needs a migration this
    task must not add. What IS guaranteed here is that a True answer can
    always be cleared: `reconcile_stale_runs`, called on the way into
    `start_run`, fails any row that can no longer be in progress, so a crashed
    run cannot lock a honeypot out permanently.
    """
    async with get_session_factory()() as db:
        found = (
            await db.execute(
                select(EvaluationRun.id).where(
                    EvaluationRun.honeypot_id == honeypot_id,
                    EvaluationRun.status == RunStatus.RUNNING,
                )
            )
        ).first()
        return found is not None
