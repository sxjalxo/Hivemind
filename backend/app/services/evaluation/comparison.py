"""Comparing two evaluation runs, and what happened to each defect.

Extracted from `runs.py`. This is the half that answers "is the flaw you
reported last week actually fixed?", and it is kept apart from orchestration
because its correctness rests on a different rule: a finding is absent from a
run for two unrelated reasons -- the fact came back `observed`, or the fact
was never established -- so resolution joins the underlying FACT status
rather than differencing finding keys.

`undetermined` is what earns the other four verdicts their credibility.
Collapsing it into `fixed` manufactures good news out of an infrastructure
failure, which is the worst answer this feature can give.
"""

import uuid
from datetime import datetime

from sqlalchemy import select

from app.db.models import EvaluationRun
from app.db.session import get_session_factory
from app.models.evaluation import (
    EvaluationRunOut,
    FindingLifecycleOut,
    RunComparison,
)
from app.services.evaluation import finding_keys, lifecycle
from app.services.evaluation.read import load_run
from app.services.evaluation.state import RunNotFoundError

_LIFECYCLE_HISTORY_LIMIT = 20


def _run_facts(run: EvaluationRunOut) -> lifecycle.RunFacts:
    """Reduce a loaded run to what lifecycle resolution needs.

    `fact_status_by_key` is rebuilt with the SAME key functions `_fact_findings`
    used to write the findings. Deriving it a second way here would let the two
    drift, and a key that does not match its own finding reads as a defect that
    is simultaneously present and never checked.

    It is built for every probe and chain row regardless of fact status --
    that is the point. A key with an `observed` fact is what proves the defect
    is genuinely gone rather than merely unexamined.
    """
    by_key: dict[str, str] = {}
    for probe in run.probe_results:
        if probe.establishes is None:
            continue
        key = (
            finding_keys.service_key(probe.establishes)
            if probe.module == "nmap"
            else finding_keys.probe_key(probe.probe_id, probe.establishes)
        )
        by_key[key] = probe.fact_status
    for step in run.chain_steps:
        by_key[finding_keys.chain_key(step.chain_id, step.expected_technique_id)] = (
            step.fact_status
        )

    return lifecycle.RunFacts(
        run_id=run.id,
        status=run.status,
        evaluator_status=run.evaluator_status,
        finding_keys=frozenset(f.finding_key for f in run.findings),
        fact_status_by_key=by_key,
    )


def _parsed_timestamp(value: str) -> datetime:
    """`EvaluationRunOut.started_at` is ISO text with a `Z`, not a datetime.

    Passing it straight into a query compares `timestamp with time zone` to
    `character varying`, which Postgres refuses outright rather than coercing
    -- the failure is loud, which is the only good thing about it.
    """
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


async def _lifecycle_history(
    honeypot_id: str, before: str, exclude: set[str]
) -> list[lifecycle.RunFacts]:
    """Earlier runs of the same honeypot, for the `regressed` test only.

    Bounded: a defect that returns after twenty runs is indistinguishable from
    a new one for any practical purpose, and an unbounded scan would grow with
    the honeypot's whole history on every comparison.

    `resolve` filters these to completed runs that actually established the
    fact, so nothing here needs to pre-judge usability -- but the ordering
    does matter: newest first, so the limit keeps the RECENT past rather than
    an arbitrary slice of the distant one.
    """
    async with get_session_factory()() as db:
        rows = (
            (
                await db.execute(
                    select(EvaluationRun.id)
                    .where(
                        EvaluationRun.honeypot_id == honeypot_id,
                        EvaluationRun.started_at < _parsed_timestamp(before),
                    )
                    .order_by(EvaluationRun.started_at.desc())
                    .limit(_LIFECYCLE_HISTORY_LIMIT)
                )
            )
            .scalars()
            .all()
        )

    history: list[lifecycle.RunFacts] = []
    for row_id in rows:
        if str(row_id) in exclude:
            continue
        run = await load_run(row_id)
        if run is not None:
            history.append(_run_facts(run))
    return history


def _lifecycle_entries(
    base: EvaluationRunOut,
    head: EvaluationRunOut,
    history: list[lifecycle.RunFacts],
    attributable: bool,
) -> list[FindingLifecycleOut]:
    """Join resolution back onto the rows a client can actually render.

    A `fixed` entry has no row in head by definition, so its text and evidence
    are read from base. Without that it would be a bare key -- the caller
    would be told something was repaired and have no way to see what.
    """
    rows = {
        base.id: {f.finding_key: f for f in base.findings},
        head.id: {f.finding_key: f for f in head.findings},
    }

    entries: list[FindingLifecycleOut] = []
    for entry in lifecycle.resolve(_run_facts(base), _run_facts(head), history):
        source_row = rows.get(entry.from_run, {}).get(entry.key)
        entries.append(
            FindingLifecycleOut(
                key=entry.key,
                status=entry.status,
                attributable=attributable,
                is_slot=entry.is_slot,
                from_run_id=entry.from_run,
                characteristic=source_row.characteristic if source_row else None,
                severity=source_row.severity if source_row else None,
                source=source_row.source if source_row else None,
                finding=source_row.finding if source_row else None,
                recommendation=source_row.recommendation if source_row else None,
                evidence=source_row.evidence if source_row else [],
            )
        )
    return entries


async def compare_runs(base_id: uuid.UUID, head_id: uuid.UUID) -> RunComparison:
    """Delta between two runs, with its attribution stated plainly.

    Never refuses a comparison. `classification` is `same_configuration` only
    when BOTH fingerprints match, and `configuration_changed` otherwise --
    but the two fingerprints carry OPPOSITE implications, so `differences`
    names exactly which moved:

      * `honeypot_fingerprint` -- the honeypot changed. That is the POINT of
        a comparison: the change is the improvement being measured, and the
        delta is attributable to it.
      * `evaluation_config_fingerprint` -- OUR probes, chains, rulebook or
        budget changed. The two runs asked different questions, so the delta
        is NOT attributable to the honeypot.

    Both still classify as `configuration_changed` because that contract is
    fixed downstream; `differences` is what makes the distinction usable.
    """
    base = await load_run(base_id)
    head = await load_run(head_id)
    if base is None:
        raise RunNotFoundError(str(base_id))
    if head is None:
        raise RunNotFoundError(str(head_id))

    differences: list[str] = []
    if base.honeypot_fingerprint != head.honeypot_fingerprint:
        differences.append("honeypot_fingerprint")
    if base.evaluation_config_fingerprint != head.evaluation_config_fingerprint:
        differences.append("evaluation_config_fingerprint")

    base_scores = {s.characteristic: s.deterministic_score for s in base.category_scores}
    head_scores = {s.characteristic: s.deterministic_score for s in head.category_scores}
    deltas: dict[str, float | None] = {}
    for characteristic in sorted(set(base_scores) | set(head_scores)):
        before = base_scores.get(characteristic)
        after = head_scores.get(characteristic)
        # None on either side means "not established". A delta against that is
        # not a delta, and inventing one would resurrect the 0.0 that None
        # exists to prevent.
        deltas[characteristic] = (
            round(after - before, 3) if before is not None and after is not None else None
        )

    # A defect that vanished across a changed evaluation config may mean we
    # stopped asking rather than that anyone fixed it -- a probe deleted from
    # probes.yaml makes its finding disappear and look repaired. The honeypot
    # fingerprint moving is the opposite: that is the change being measured.
    attributable = "evaluation_config_fingerprint" not in differences
    history = await _lifecycle_history(
        head.honeypot_id, before=base.started_at, exclude={base.id, head.id}
    )

    return RunComparison(
        base=base,
        head=head,
        classification="same_configuration" if not differences else "configuration_changed",
        differences=differences,
        deltas=deltas,
        findings=_lifecycle_entries(base, head, history, attributable),
    )
