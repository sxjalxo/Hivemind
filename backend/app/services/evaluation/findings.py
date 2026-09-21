"""Turning what a run established into findings a developer can act on.

Extracted from `runs.py`. A finding is not a second opinion about a fact --
it is the same fact, expressed as something to fix, and that is why this is
built from the collected rows rather than from anything the evaluator said.

The rule that shapes every function here: a `not_observed` fact is a defect
and becomes a finding; an `unknown` one is OUR failure to look and must never
become one. Manufacturing a finding out of a probe that timed out reports an
infrastructure problem as a honeypot defect, which is the failure this whole
subsystem is built to avoid.
"""

import uuid

from app.db.models import (
    Characteristic,
    EvaluationChainStep,
    EvaluationEvidence,
    EvaluationFinding,
    EvaluationProbeResult,
    EvidenceKind,
    FactStatus,
)
from app.services.chunking import MAX_ITEM_CHARS, truncate_text
from app.services.evaluation import finding_keys, sanity
from app.services.evaluation.state import Collected as _Collected
from app.services.evaluation.state import PendingFinding

_PROBE_SEVERITY = "medium"


_CHAIN_SEVERITY = "high"


def _probe_summary(row: EvaluationProbeResult) -> str:
    return (
        f"probe {row.probe_id} (module {row.module}) "
        f"establishes {row.establishes or 'nothing declared'}; "
        f"fact_status={row.fact_status}; output: {row.raw_output or '(no output)'}"
    )


def _chain_summary(row: EvaluationChainStep) -> str:
    return (
        f"chain {row.chain_id} step {row.step_index} expected "
        f"{row.expected_technique_id}; fact_status={row.fact_status}; "
        f"matched_rule={row.matched_rule_id or 'none'}; "
        f"command: {row.command or '(no matching command)'}"
    )


def _severity_for(rating: float) -> str:
    """`EvaluationFinding.severity` is NOT NULL, so a value is required.

    This is a rendering of the evaluator's OWN rating into the severity
    vocabulary the rest of the system uses, not a second independent
    judgement. The bands are stated here so the mapping is auditable rather
    than buried.
    """
    if rating < 0.34:
        return "high"
    if rating < 0.67:
        return "medium"
    return "low"


def _evidence_for(finding_id: uuid.UUID, cited: list[str]) -> list[EvaluationEvidence]:
    rows: list[EvaluationEvidence] = []
    for citation in cited:
        prefix, _, raw = citation.partition(":")
        try:
            row_id = uuid.UUID(raw)
        except ValueError:
            # The truncation notice, or anything else that is not a row id.
            continue
        if prefix == "probe":
            rows.append(
                EvaluationEvidence(
                    finding_id=finding_id, kind=EvidenceKind.PROBE, probe_result_id=row_id
                )
            )
        elif prefix == "chain":
            rows.append(
                EvaluationEvidence(
                    finding_id=finding_id, kind=EvidenceKind.CHAIN_STEP, chain_step_id=row_id
                )
            )
    return rows


def fact_findings(run_id: uuid.UUID, collected: _Collected) -> None:
    """Promote `not_observed` facts into findings.

    No new analysis happens here. These facts were already collected, already
    scored and already carry a row that grounds them -- they were simply never
    expressed as findings, so a run on the normal no-BYOK configuration
    produced nothing a lifecycle could track. The only judgement added is a
    severity per source.

    `observed` produces nothing: there is no defect. `unknown` produces
    nothing either, and that is the rule the whole lifecycle rests on --
    `unknown` means OUR probe failed, not that the honeypot lacks the thing.
    A finding built from it would enter defect history as a regression on the
    run it happened and as a fix on the next one, manufacturing both out of an
    infrastructure failure. Same reason `unknown` is excluded from both sides
    of the scoring fraction.

    One finding per key. Two rows for one probe -- a retry, a duplicated
    observation -- would violate the unique index on
    `(run_id, finding_key)` at FLUSH, taking the whole run's persistence down
    rather than merely duplicating a row.
    """
    seen: set[str] = set()

    def _add(key: str, characteristic: str, severity: str, text: str, evidence) -> None:
        if key in seen:
            return
        seen.add(key)
        finding = EvaluationFinding(
            run_id=run_id,
            characteristic=characteristic,
            severity=severity,
            finding=truncate_text(text, MAX_ITEM_CHARS),
            recommendation=None,
            source="deterministic",
            finding_key=key,
        )
        collected.findings.append(
            PendingFinding(finding=finding, evidence=evidence(finding.id))
        )

    for row in collected.probe_rows:
        if row.fact_status != FactStatus.NOT_OBSERVED:
            continue
        # nmap observations land in `probe_rows` alongside the agent's, so the
        # module is what separates a missing service from a missing file.
        is_service = row.module == "nmap"
        key = (
            finding_keys.service_key(row.establishes)
            if is_service
            else finding_keys.probe_key(row.probe_id, row.establishes)
        )
        text = (
            f"expected service {row.establishes} was not found"
            if is_service
            else f"{row.probe_id} did not establish {row.establishes}"
        )
        _add(
            key,
            collected.characteristic_by_probe_row.get(row.id, Characteristic.CONTEXT.value),
            _PROBE_SEVERITY,
            text,
            lambda finding_id, row=row: [
                EvaluationEvidence(
                    finding_id=finding_id,
                    kind=EvidenceKind.PROBE,
                    probe_result_id=row.id,
                )
            ],
        )

    for step in collected.chain_rows:
        if step.fact_status != FactStatus.NOT_OBSERVED:
            continue
        _add(
            finding_keys.chain_key(step.chain_id, step.expected_technique_id),
            Characteristic.ATTACK_POSSIBILITIES.value,
            # An attack that cannot be carried out is a larger tell than one
            # absent file: it is the difference between a honeypot that looks
            # slightly wrong and one that cannot be used for what an intruder
            # came to do.
            _CHAIN_SEVERITY,
            f"chain {step.chain_id}: expected technique "
            f"{step.expected_technique_id} was not observed",
            lambda finding_id, step=step: [
                EvaluationEvidence(
                    finding_id=finding_id,
                    kind=EvidenceKind.CHAIN_STEP,
                    chain_step_id=step.id,
                )
            ],
        )


def contradiction_findings(
    run_id: uuid.UUID, collected: _Collected, observations: list[sanity.Observation]
) -> None:
    """Two completed probes that disagree about the same canonical fact.

    Deterministic, evidence-grounded and directly attacker-visible: a shell
    whose `hostname` and `/etc/hostname` disagree is a tell. Severity is
    `high` for that reason -- it is not a judgement call about realism, it is
    an internal inconsistency the honeypot itself exhibited.
    """
    by_probe_id: dict[str, EvaluationProbeResult] = {}
    for row in collected.probe_rows:
        by_probe_id.setdefault(row.probe_id, row)

    for contradiction in sanity.find_contradictions(observations):
        rows = [by_probe_id.get(probe_id) for probe_id in contradiction.probe_ids]
        grounded = [row for row in rows if row is not None]
        if not grounded:
            continue
        finding = EvaluationFinding(
            run_id=run_id,
            characteristic=Characteristic.SANITY.value,
            severity="high",
            finding=truncate_text(
                f"{contradiction.probe_ids[0]} and {contradiction.probe_ids[1]} disagree about "
                f"{contradiction.fact}: {contradiction.values[0]!r} vs "
                f"{contradiction.values[1]!r}",
                MAX_ITEM_CHARS,
            ),
            recommendation=None,
            source="deterministic",
            finding_key=finding_keys.sanity_key(
                contradiction.fact, contradiction.probe_ids
            ),
        )
        collected.findings.append(
            PendingFinding(
                finding=finding,
                evidence=[
                    EvaluationEvidence(
                        finding_id=finding.id,
                        kind=EvidenceKind.PROBE,
                        probe_result_id=row.id,
                    )
                    for row in grounded
                ],
            )
        )


# --- persistence -------------------------------------------------------

_PENDING_EVIDENCE = "evaluation_pending_evidence"


def stage_finding(db, pending: PendingFinding) -> None:
    """Queue one finding plus its evidence on `db`. Nothing is written yet.

    The evidence is parked in the session's own scratch space so it cannot
    be forgotten between the finding's INSERT and the COMMIT the deferred
    trigger checks at.
    """
    db.add(pending.finding)
    db.info.setdefault(_PENDING_EVIDENCE, []).extend(pending.evidence)


async def flush_findings(db) -> None:
    """Flush findings, then their evidence, inside the caller's transaction.

    Findings first because `evaluation_evidence.finding_id` is an ordinary,
    immediate foreign key -- only the "has at least one evidence row" check is
    deferred. The caller commits; the trigger fires there.
    """
    await db.flush()
    pending = db.info.pop(_PENDING_EVIDENCE, [])
    for evidence in pending:
        db.add(evidence)
    await db.flush()
