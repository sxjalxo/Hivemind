"""Run every evaluation module in order, persist the result, compare two runs.

This is the module that turns Tasks 4-13 into one evaluation. Three
disciplines from those tasks are load-bearing here and none of them may be
relaxed for convenience:

**Our own failure is never evidence against the honeypot.** A module that
times out or blows up leaves the facts it would have established `unknown`,
and `scoring.score_characteristics` excludes `unknown` from both numerator
and denominator. Nothing in this module ever converts a failure into `0.0`.

**Two assessments are never combined.** `deterministic_score` answers "did
the honeypot do the checkable things?"; `evaluator_rating` answers "would an
attacker believe it?". They are stored in two columns, compared separately,
and there is deliberately no composite anywhere.

**`None` means "not established"** and must never render as 0.

Stage order, and why it is not the order the plan's draft proposed:

    reset -> honeypot fingerprint -> config fingerprint -> INSERT run row
      -> start capture -> nmap -> agent probes -> chains -> stop capture
      -> deterministic scoring -> evaluator -> persist

The draft had the run row inserted first, with the fingerprints captured
afterwards. That is not representable: `EvaluationRun.honeypot_fingerprint`
and `.evaluation_config_fingerprint` are both NOT NULL and both fingerprint
functions RAISE rather than degrade (`fingerprints.FingerprintError`), by a
deliberate ruling -- a fingerprint that silently lies asserts comparability
that was never checked. There is no representable "unknown fingerprint" run,
so the row cannot exist until both values do.

`honeypot_fingerprint` is sampled AFTER the reset and BEFORE any module runs,
against the same container the reset just cleared. Sampling it anywhere else
fingerprints a different honeypot than the one evaluated.

Reset ABORTS the run rather than degrading it. `nmap`/`tcpdump`/`agent`
produce evidence, so their failures become `unknown` facts. Reset produces no
evidence -- it establishes the precondition under which this run's evidence
means anything. A failed reset means this run may be observing the previous
run's residue, and reset is per-path sequential, so a failure part-way
through is not "nothing changed". Any comparison drawn from such a run is
unsound, so `start_run` raises and no run row is created at all. Task 15
surfaces that to the caller. Note `ResetBoundaryError` is a `ValueError`, not
a `ResetError`; nothing here catches either, so both propagate.

Capture stops BEFORE deterministic scoring rather than after (the spec's §6
sketch has them the other way round). tcpdump's `network.activity` fact only
exists once the capture has been drained, and scoring is a pure function over
whatever observations exist -- running it after the drain is what lets that
fact be scored at all, and costs nothing.

**A measurement is never lost to our own crash.** Both of the steps above --
recording the drained capture, and scoring -- run in `_execute_run`'s
`finally`, not on its happy path. Anything raised in the orchestration frame
itself (an `_emit` to a dead queue, the capture failing to start, the
chain-row build) used to skip them, so `_persist` saw no scores and wrote
FAILED over probe rows holding `observed` facts in the very same transaction.
That is the module's own first discipline inverted: our failure erasing a real
measurement and reporting it as the honeypot's. For the same reason
`_run_status` falls back to the collected rows when scoring itself could not
run, and `reconcile_stale_runs` clears a RUNNING row left behind by a process
that died before any `finally` could run at all.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from app.auth import Actor
from app.config import get_settings
from app.db.models import (
    Characteristic,
    EvaluationCategoryScore,
    EvaluationChainStep,
    EvaluationEvidence,
    EvaluationFinding,
    EvaluationModuleResult,
    EvaluationProbeResult,
    EvaluationRun,
    EvaluatorStatus,
    FactStatus,
    ModuleStatus,
    RunStatus,
)
from app.db.session import get_session_factory
from app.models.evaluation import (
    EVALUATION_STAGES,
    EvaluationProgressEvent,
    LiveEvaluationMetrics,
)
from app.services.chunking import MAX_ITEM_CHARS, truncate_text
from app.services.evaluation import agent as agent_module
from app.services.evaluation import chain_runner
from app.services.evaluation import (
    finding_keys,
    fingerprints,
    probes,
    sanity,
    scoring,
    targets,
)
from app.services.evaluation.agent import AgentBudget, EvaluationTarget
from app.services.evaluation.evaluator import EvidenceItem, evaluate_characteristic
from app.services.evaluation.findings import (
    contradiction_findings as _contradiction_findings,
)
from app.services.evaluation.findings import _chain_summary, _evidence_for
from app.services.evaluation.findings import _probe_summary, _severity_for
from app.services.evaluation.findings import fact_findings as _fact_findings
from app.services.evaluation.findings import flush_findings as _flush_findings
from app.services.evaluation.findings import stage_finding as _stage_finding
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.reset import ResetBoundaryError, ResetError, reset_target
from app.services.evaluation.state import PendingFinding, RunNotFoundError
from app.services.evaluation.state import Collected as _Collected
from app.services.evaluation.static import nmap as nmap_module
from app.services.evaluation.static import tcpdump
from app.services.evaluation.static.chains import ChainStepResult
from app.services.llm.base import LLMClient
from app.services.llm.byok import ByokClient
from app.workers.queue import evaluation_job_key, get_queue

logger = logging.getLogger(__name__)

__all__ = [
    "ResetBoundaryError",
    "ResetError",
    "RunNotFoundError",
    "compare_runs",
    "delete_run",
    "is_running",
    "list_run_summaries",
    "list_runs",
    "load_run",
    "reconcile_orphaned_runs_at_startup",
    "reconcile_stale_runs",
    "start_run",
]

# `EvaluationModuleResult.detail` and every other stored error string is
# bounded here, matching `container.ERROR_DETAIL_LIMIT` and
# `evaluator._DETAIL_LIMIT`. A `ResetError`/`ContainerExecError` message is
# already bounded upstream; an arbitrary exception's str() is not.
DETAIL_LIMIT = 500

# The two detail strings this module owns. `evaluator.py` builds its own for
# the causes it can see; these cover the two it cannot.
NO_EVIDENCE_DETAIL = "no evidence gathered for this characteristic"
REJECTED_CITATIONS_DETAIL = "verdict rejected: no cited evidence resolved"

# The observation `value` kept as the readable fact. The full text goes to
# `raw_output`, itself bounded -- command output is attacker-sized and an
# unbounded column turns one `base64 /dev/urandom` into a multi-megabyte row.
VALUE_LIMIT = 500

# --- evidence package bounds -------------------------------------------
#
# `evaluator.evaluate_characteristic` bounds each ITEM (`truncate_text(summary,
# MAX_ITEM_CHARS)` = 13,136 chars) and nothing bounds the package as a whole:
# N items x 13,136 is still unbounded, on the user's own paid BYOK key, once
# per characteristic. These two bound the total.
#
# Items are truncated rather than dropped wherever possible: `truncate_text`
# leaves a counted, visible omission marker, so the model can see it is
# reading an excerpt. Dropping items silently would hide evidence from the
# judgement without saying so. Past MAX_PACKAGE_ITEMS dropping is unavoidable,
# and a visible notice item is appended saying how many went.
MAX_PACKAGE_ITEMS = 40
MAX_PACKAGE_CHARS = 60_000
MIN_ITEM_CHARS = 400
TRUNCATION_NOTICE_ID = "package-truncation-notice"

# --- stale-run reconciliation ------------------------------------------
#
# A run that dies between its INSERT and `_persist` -- the process is killed,
# or the database goes away and `_force_terminal` fails too -- leaves
# `status=running, finished_at=NULL` with nothing left in the system to
# finish it. `is_running` then answers True for that honeypot forever, and
# Task 15's 409 would lock the honeypot out permanently with no code path to
# clear it. So this module reconciles those rows itself.
#
# The cutoff is DERIVED, not guessed: a run cannot outlive the sum of every
# bound it is subject to. A row older than that cannot still be in progress,
# so reconciling it can never terminate a live run -- which is what makes it
# safe to sweep on the way into `start_run` rather than only at startup.
STALE_RUN_MARGIN_SECONDS = 600
# `ByokClient` gives httpx a 300s timeout and `_evaluate` issues one call per
# characteristic, sequentially, with no retry.
_EVALUATOR_WORST_CASE_SECONDS = 300 * len(Characteristic)


class TargetUnreachableError(RuntimeError):
    """Nothing accepted a connection at the configured evaluation target.

    A precondition, not evidence. Every module would still *run* against an
    unreachable target -- the agent would time out per command, nmap would
    find nothing, the chains would execute against a closed socket -- and
    each would correctly degrade its facts to `unknown`. The run would
    complete, score nothing, and take the full agent budget to do it.

    That is technically honest and practically useless: an all-`unknown` run
    is indistinguishable at a glance from a honeypot that answered badly, and
    the developer has to read module statuses to discover the target was
    never there. Failing here instead costs one TCP connect and names the
    setting to fix.
    """


# --- seams -------------------------------------------------------------
#
# Thin module-level indirections so tests can replace EVERY subprocess and SSH
# boundary. No test may open a real SSH connection, run docker, run nmap or
# run tcpdump: those all touch the live honeypot, which holds real captured
# session data.

_reset_target = reset_target
# Chain execution moved to `chain_runner`; this stays a seam here because
# `_execute_run` calls it and the suite patches it by this name. The
# functions chain_runner calls INTERNALLY are patched on that module.
_run_chains = chain_runner.run_chains
_honeypot_fingerprint = fingerprints.honeypot_fingerprint
_evaluation_config_fingerprint = fingerprints.evaluation_config_fingerprint
_capture = tcpdump.capture
_score = scoring.score_characteristics


def _evaluator_client() -> LLMClient | None:
    """The BYOK evaluator, or None. NEVER the local model.

    `llm.get_recommendation_client()` falls back to Ollama; that is right
    for the analysis pipeline's recommendation stage and wrong here. The source paper measured sub-70b models
    as returning "only superficial results" for the realism-judgement role,
    and a shallow-but-plausible realism verdict is the exact failure this
    system exists to prevent. No key means `evaluator_status=UNAVAILABLE`,
    reported as such, with the deterministic measurement fully intact.

    A key WITH an unsupported `BYOK_PROVIDER` is a different thing entirely:
    `ByokClient.__init__` raises `ValueError`, and that exception is left to
    propagate to `_evaluate`, which reports it as EVALUATOR_FAILED. It must
    never be swallowed into `None` -- UNAVAILABLE means "no evaluator was
    configured", i.e. we never tried, and a misconfiguration reported that way
    is indistinguishable from an empty .env.
    """
    settings = get_settings()
    if settings.byok_api_key and settings.byok_provider and settings.byok_model:
        return ByokClient(settings.byok_provider, settings.byok_api_key, settings.byok_model)
    return None


async def _run_nmap(target: str, timeout_seconds: int, ssh_port: int) -> ModuleOutcome:
    return await nmap_module.scan(target, timeout_seconds, ssh_port)


async def _run_agent(target: EvaluationTarget, budget: AgentBudget) -> ModuleOutcome:
    return await agent_module.run_probes(target, budget)


def _agent_model() -> str:
    """What drove the agent. `EvaluationRun.agent_model` is NOT NULL.

    `agent.run_probes` is deterministic -- paramiko plus a fixed probe list
    from probes.yaml -- so there is no model here at all. Writing the local
    Ollama model name would be a plain lie: that model never saw this run, and
    a reader comparing two runs would attribute a difference to a model change
    that never happened. What actually determines what the agent can find is
    the probe set, so the column records exactly that.

    The version is read through `probes._raw()` rather than the module-level
    `PROBE_SET_VERSION` snapshot, for the reason `fingerprints._config_parts`
    documents: `_raw()` and `load_probes()` share one `@lru_cache` entry, so
    this string and the probes the run actually executed can never come from
    two different reads of the file.
    """
    return f"deterministic-probes@{probes._raw()['version']}"


async def _emit(run_id: uuid.UUID, stage_index: int, **metrics: int) -> None:
    await get_queue().publish(
        evaluation_job_key(str(run_id)),
        EvaluationProgressEvent(
            stage_index=stage_index,
            stage=EVALUATION_STAGES[stage_index],
            metrics=LiveEvaluationMetrics(
                progress_pct=int((stage_index + 1) / len(EVALUATION_STAGES) * 100),
                **metrics,
            ),
        ),
    )


def _bounded(text: str | None, limit: int) -> str | None:
    return truncate_text(text, limit) if text else text


def _module_row(
    run_id: uuid.UUID,
    module: str,
    module_status: str,
    detail: str | None,
    started: datetime,
) -> EvaluationModuleResult:
    return EvaluationModuleResult(
        run_id=run_id,
        module=module,
        module_status=module_status,
        detail=_bounded(detail, DETAIL_LIMIT),
        started_at=started,
        finished_at=datetime.now(timezone.utc),
    )


def _characteristic_for(module: str, probe_id: str, by_probe_id: dict[str, str]) -> str:
    """Which characteristic one observation belongs to.

    Agent probes declare theirs in probes.yaml. nmap establishes service
    facts and tcpdump establishes environmental context; neither has a
    per-probe declaration, so the module itself names the characteristic.
    """
    if module == "nmap":
        return Characteristic.SERVICES.value
    if module == "tcpdump":
        return Characteristic.CONTEXT.value
    return by_probe_id.get(probe_id, Characteristic.CONTEXT.value)


def _record_outcome(
    run_id: uuid.UUID,
    collected: _Collected,
    outcome: ModuleOutcome,
    target: str,
    started: datetime,
    by_probe_id: dict[str, str],
    observations_by_characteristic: dict[str, list[sanity.Observation]],
    all_observations: list[sanity.Observation],
) -> None:
    collected.modules.append(
        _module_row(run_id, outcome.module, outcome.module_status, outcome.detail, started)
    )
    for observation in outcome.observations:
        characteristic = _characteristic_for(outcome.module, observation.probe_id, by_probe_id)
        row = EvaluationProbeResult(
            run_id=run_id,
            module=outcome.module,
            probe_id=observation.probe_id,
            target=target,
            establishes=observation.establishes,
            value=_bounded(observation.value, VALUE_LIMIT),
            fact_status=observation.fact_status,
            raw_output=_bounded(observation.value, MAX_ITEM_CHARS),
            completed_at=datetime.now(timezone.utc),
        )
        collected.probe_rows.append(row)
        collected.characteristic_by_probe_row[row.id] = characteristic
        observations_by_characteristic.setdefault(characteristic, []).append(observation)
        all_observations.append(observation)


def _unknown_probe_observations() -> list[sanity.Observation]:
    """Every probe the agent would have run, left `unknown`.

    Used when the agent stage raises before producing an outcome of its own.
    Scoring treats an absent observation and an `unknown` one identically
    (both are excluded from numerator and denominator), so this changes no
    score -- it makes the gap visible in `evaluation_probe_results` instead of
    leaving a reader to infer it from a missing row.
    """
    return [
        sanity.Observation(
            probe_id=probe.id,
            establishes=probe.establishes,
            value=None,
            fact_status=FactStatus.UNKNOWN,
        )
        for probe in probes.load_probes()
    ]


# --- evidence packaging ------------------------------------------------


def _bound_package(items: list[EvidenceItem]) -> list[EvidenceItem]:
    """Bound the WHOLE package, not just each item. See MAX_PACKAGE_CHARS.

    The truncation notice is deliberately still an ordinary package item, and
    therefore still citable as far as `evaluate_characteristic` is concerned:
    the model has to SEE that items were omitted, and anything rendered into
    the prompt is by construction in that function's `offered` set. What stops
    it grounding a verdict is downstream, in `_evaluate`: its id does not parse
    as a row id, so a verdict citing only it resolves to no evidence and is
    dropped -- finding AND rating together.
    """
    kept = items[:MAX_PACKAGE_ITEMS]
    dropped = len(items) - len(kept)
    if kept:
        share = min(MAX_ITEM_CHARS, max(MIN_ITEM_CHARS, MAX_PACKAGE_CHARS // len(kept)))
        kept = [
            EvidenceItem(id=item.id, summary=truncate_text(item.summary, share)) for item in kept
        ]
    if dropped:
        kept.append(
            EvidenceItem(
                id=TRUNCATION_NOTICE_ID,
                summary=(
                    f"{dropped} further evidence items for this characteristic were omitted "
                    f"to bound the package; this notice is not itself evidence"
                ),
            )
        )
    return kept


def _build_packages(collected: _Collected) -> dict[str, list[EvidenceItem]]:
    """One evidence package per characteristic.

    Ids are `probe:<uuid>` / `chain:<uuid>` so a cited id resolves back to a
    real persisted row: the evaluator references evidence, it never creates
    it, and a finding must be groundable in something that exists.
    """
    packages: dict[str, list[EvidenceItem]] = {}
    for row in collected.probe_rows:
        characteristic = collected.characteristic_by_probe_row[row.id]
        packages.setdefault(characteristic, []).append(
            EvidenceItem(id=f"probe:{row.id}", summary=_probe_summary(row))
        )
    for row in collected.chain_rows:
        packages.setdefault(Characteristic.ATTACK_POSSIBILITIES.value, []).append(
            EvidenceItem(id=f"chain:{row.id}", summary=_chain_summary(row))
        )
    return {
        characteristic: _bound_package(items) for characteristic, items in packages.items()
    }


def _aggregate_evaluator_status(statuses: list[str]) -> str:
    """Collapse one status per characteristic into the run's single column.

    `EvaluationRun.evaluator_status` is one column per run; the evaluator
    returns one status per characteristic. The rule is worst-case, with
    EVALUATOR_FAILED dominating:

      any EVALUATOR_FAILED -> EVALUATOR_FAILED
      else any COMPLETED   -> COMPLETED
      else                 -> UNAVAILABLE

    EVALUATOR_FAILED outranks COMPLETED because it is the one status meaning
    "something broke on our side and a rating you would expect is missing" --
    a consumer must see that from the run header without walking every
    category. COMPLETED outranks UNAVAILABLE because at least one
    characteristic genuinely received a verdict, and the per-category
    `evaluator_rating IS NULL` already shows which did not.

    What this column loses, and where to find it: which characteristics failed,
    and why. Both now live on `EvaluationCategoryScore.evaluator_status` and
    `.evaluator_detail`, one row per characteristic. This column stays a
    header summary -- a consumer must be able to see "something broke" from
    the run without walking every category -- but it is no longer the only
    record, and `lifecycle.state` reads the per-characteristic column instead
    of this one precisely because this one cannot tell a never-assessed
    characteristic from an assessed one.
    """
    if EvaluatorStatus.EVALUATOR_FAILED in statuses:
        return EvaluatorStatus.EVALUATOR_FAILED
    if EvaluatorStatus.COMPLETED in statuses:
        return EvaluatorStatus.COMPLETED
    return EvaluatorStatus.UNAVAILABLE


async def _evaluate(
    run_id: uuid.UUID, collected: _Collected, packages: dict[str, list[EvidenceItem]]
) -> None:
    """One paid call per characteristic, issued SEQUENTIALLY.

    One context per characteristic is the design (the paper found merged
    prompts markedly shallower), so cost scales with characteristic count.
    They are serialized rather than gathered because there is no retry or
    backoff anywhere in this path: a 429 becomes EVALUATOR_FAILED immediately
    and permanently for that characteristic. Firing every call at once
    maximises the chance of tripping a provider rate limit, and every trip is
    unrecoverable. Sequential also makes spend predictable.

    `evaluate_characteristic` never raises, so the status is CHECKED rather
    than assumed: UNAVAILABLE (both reasons) and EVALUATOR_FAILED all return
    `verdict is None`.
    """
    # Recorded FIRST, before anything here can fail. `_resolved_evaluator_outcome`
    # reads it to tell "the evaluator ran and never saw this characteristic"
    # from "the evaluator never ran at all" -- the stages before this one are
    # all caught, so `_persist` is reachable without this function having been
    # entered, and only one of those two supports the NO_EVIDENCE_DETAIL claim.
    collected.evaluator_ran = True
    try:
        client = _evaluator_client()
    except ValueError as exc:
        # An unsupported `BYOK_PROVIDER` with a key and a model set. This is
        # OUR misconfiguration and it must not report as UNAVAILABLE, which
        # means "no evaluator was configured" -- i.e. we never tried. Reported
        # that way, `BYOK_PROVIDER=gemini` with a real key is indistinguishable
        # from an empty .env. EVALUATOR_FAILED is the status that means
        # "something broke on our side and a rating you would expect is
        # missing", which is exactly what happened.
        logger.error("BYOK evaluator is misconfigured on run %s: %s", run_id, exc)
        collected.evaluator_model = None
        collected.evaluator_status = EvaluatorStatus.EVALUATOR_FAILED
        # Every characteristic we HAD evidence for would have been assessed
        # and was not. One with no package was never going to be assessed
        # regardless of the key, and `_resolved_evaluator_outcome` reports
        # that separately and correctly.
        for characteristic in packages:
            collected.evaluator_outcomes[characteristic] = (
                EvaluatorStatus.EVALUATOR_FAILED,
                # Bounded like every other stored detail: `exc` carries a
                # settings-derived string into a text column.
                _bounded(f"BYOK evaluator misconfigured: {exc}", DETAIL_LIMIT),
            )
        return

    collected.evaluator_model = client.model_name if client is not None else None

    for characteristic, package in packages.items():
        outcome = await evaluate_characteristic(client, characteristic, package)
        if outcome.verdict is None:
            logger.info(
                "evaluator produced no verdict for %s on run %s: %s (%s)",
                characteristic,
                run_id,
                outcome.status,
                outcome.detail,
            )
            collected.evaluator_outcomes[characteristic] = (
                outcome.status,
                _bounded(outcome.detail, DETAIL_LIMIT),
            )
            continue

        verdict = outcome.verdict
        finding = EvaluationFinding(
            run_id=run_id,
            characteristic=characteristic,
            severity=_severity_for(verdict.rating),
            finding=truncate_text(verdict.critique, MAX_ITEM_CHARS),
            recommendation=_bounded(verdict.recommendation, MAX_ITEM_CHARS),
            source="evaluator",
            finding_key=finding_keys.evaluator_key(characteristic),
        )
        evidence = _evidence_for(finding.id, verdict.cited_evidence_ids)
        if not evidence:
            # Every citation resolved to nothing persistable -- reachable via
            # TRUNCATION_NOTICE_ID, which is a legitimate member of `offered`
            # (so `evaluate_characteristic` accepts the verdict) but does not
            # parse as a row id (so `_evidence_for` skips it).
            #
            # The finding is dropped here, loudly: one with no evidence is
            # rejected at COMMIT by design, and writing it would take the
            # run's other results down with it. The RATING is dropped WITH it,
            # which is why the assignment below sits under this check and not
            # above it. `evaluator.py`'s own rule is that an uncited rating is
            # as ungrounded as an invented one; a rating that outlived its
            # finding would render as a realism verdict with no critique, no
            # recommendation and no evidence, indistinguishable from a
            # grounded one -- the shallow-but-plausible verdict this system
            # exists to prevent.
            logger.warning(
                "dropping evaluator finding for %s on run %s: no cited evidence resolved",
                characteristic,
                run_id,
            )
            collected.evaluator_outcomes[characteristic] = (
                EvaluatorStatus.EVALUATOR_FAILED,
                REJECTED_CITATIONS_DETAIL,
            )
            continue
        collected.ratings[characteristic] = verdict.rating
        collected.evaluator_outcomes[characteristic] = (EvaluatorStatus.COMPLETED, None)
        collected.findings.append(PendingFinding(finding=finding, evidence=evidence))

    # Derived from what was RECORDED per characteristic, never from a parallel
    # list of what `evaluate_characteristic` returned. Those two disagree on
    # the rejected-citations path: the evaluator returns COMPLETED there, and
    # then the verdict is dropped and the row records EVALUATOR_FAILED. A run
    # header reading "Evaluator completed" over six blank ratings is the same
    # unsupported positive claim the per-characteristic columns exist to stop,
    # so the header is computed from the rows it summarises.
    collected.evaluator_status = _aggregate_evaluator_status(
        [status for status, _ in collected.evaluator_outcomes.values()]
    )


def _established_anything(collected: _Collected) -> bool:
    """Did the run determine even one fact, either way?

    Exactly `scoring._fraction_observed`'s own boundary, read off the collected
    rows instead of the scores: a fact counts as established when its status is
    not `unknown`, and `observed` and `not_observed` both count (a honeypot
    that genuinely failed a check was still measured).

    This exists so the run's status does not depend on scoring having run.
    Scoring is a pure function and a failure in it -- or anywhere else in the
    orchestration frame -- is OURS. Deciding the status from `scores` alone
    made our own failure erase a real measurement and report it as the
    honeypot establishing nothing.
    """
    return any(
        row.fact_status != FactStatus.UNKNOWN
        for row in (*collected.probe_rows, *collected.chain_rows)
    )


def _run_status(collected: _Collected) -> str:
    """COMPLETED unless the run established nothing at all.

    The boundary is exact and testable: `scoring._fraction_observed` returns
    None precisely when every fact it was given was `unknown` (or there were
    none), because `unknown` is excluded from numerator and denominator alike.
    So "established nothing meaningful" is exactly "every characteristic
    scored None", and that is FAILED. Anything else -- even a single
    characteristic with a real fraction, even 0.0, which is a genuine
    measurement of a honeypot that failed every checkable thing -- is
    COMPLETED.

    `collected.scores` alone is not enough to decide that, which is the point
    of the second check. Scores are computed in `_execute_run`'s `finally` so
    an exception in the orchestration frame cannot lose them, but `_score`
    itself can fail, and then the dict is empty while `evaluation_probe_results`
    holds `observed` facts that would have scored. FAILED there would state
    that the honeypot established nothing, on the evidence of rows saying it
    did -- our failure reported as its own. So a run that established any fact
    is COMPLETED whether or not scoring got as far as expressing it as a
    number. Nothing is invented to fill the gap: the score stays absent.

    A run is never left RUNNING: `start_run`'s `finally` always writes one of
    these two, and `reconcile_stale_runs` covers the case where the process
    died before that `finally` could run at all.
    """
    if any(score is not None for score in collected.scores.values()):
        return RunStatus.COMPLETED
    if _established_anything(collected):
        return RunStatus.COMPLETED
    return RunStatus.FAILED


def _resolved_evaluator_outcome(
    collected: _Collected, characteristic: str
) -> tuple[str, str | None]:
    """The status and detail to store for one characteristic's score row.

    A characteristic with no recorded outcome was never sent to the evaluator,
    and there are two ways that happens:

    `_evaluate` RAN and never saw it. `_build_packages` creates an entry only
    for a characteristic with at least one probe or chain row, so one with
    neither is never passed to `evaluate_characteristic`. That is the same
    situation the empty-package branch reports, so it gets the same answer --
    `NO_EVIDENCE_DETAIL` -- rather than `unrecorded`, which means "this row
    predates the column" and would be a lie here.

    `_evaluate` NEVER RAN. `_finalize`, `_fact_findings`,
    `_contradiction_findings` and an unguarded `_emit` all execute before it
    and `start_run` catches whatever they raise, so `_persist` still writes
    the scores it collected. Saying "no evidence gathered for this
    characteristic" then states a reason that is false -- evidence WAS
    gathered, and the evaluator simply never got to it. The status stays
    `unavailable`, which is true either way, and the detail is NULL: the
    schema's documented "no reason was recorded", which is not the same as
    "there was no reason" and is exactly what happened.
    """
    recorded = collected.evaluator_outcomes.get(characteristic)
    if recorded is not None:
        return recorded
    return (
        EvaluatorStatus.UNAVAILABLE,
        NO_EVIDENCE_DETAIL if collected.evaluator_ran else None,
    )


async def _persist(run_id: uuid.UUID, collected: _Collected) -> None:
    """Write everything the run collected, in ONE transaction.

    Order inside it matters twice over. Probe results and chain steps go in
    before evidence, because `evaluation_evidence` carries immediate foreign
    keys to both. Findings and their evidence go in together, because the
    "every finding has evidence" trigger is DEFERRED and fires at COMMIT --
    committing a finding and adding its evidence afterwards would be
    rejected, and is unrepresentable here.
    """
    async with get_session_factory()() as db:
        run = await db.get(EvaluationRun, run_id)
        if run is None:  # pragma: no cover - the row is inserted by start_run
            raise RunNotFoundError(str(run_id))

        run.status = _run_status(collected)
        run.finished_at = datetime.now(timezone.utc)
        run.evaluator_status = collected.evaluator_status
        run.evaluator_model = collected.evaluator_model

        for row in collected.modules:
            db.add(row)
        for row in collected.probe_rows:
            db.add(row)
        for row in collected.chain_rows:
            db.add(row)
        for characteristic, score in collected.scores.items():
            status, detail = _resolved_evaluator_outcome(collected, characteristic)
            db.add(
                EvaluationCategoryScore(
                    run_id=run_id,
                    characteristic=characteristic,
                    deterministic_score=score,
                    # None, never 0.0, when the evaluator produced no verdict.
                    evaluator_rating=collected.ratings.get(characteristic),
                    evaluator_status=status,
                    evaluator_detail=detail,
                )
            )
        # A characteristic the evaluator rated but scoring did not reach still
        # deserves its row -- with deterministic_score None, not 0.0.
        for characteristic, rating in collected.ratings.items():
            if characteristic not in collected.scores:
                status, detail = _resolved_evaluator_outcome(collected, characteristic)
                db.add(
                    EvaluationCategoryScore(
                        run_id=run_id,
                        characteristic=characteristic,
                        deterministic_score=None,
                        evaluator_rating=rating,
                        evaluator_status=status,
                        evaluator_detail=detail,
                    )
                )
        await db.flush()

        for pending in collected.findings:
            _stage_finding(db, pending)
        await _flush_findings(db)

        await db.commit()


async def _force_terminal(run_id: uuid.UUID) -> None:
    """Last resort: a run must never be left RUNNING.

    Only reachable when `_persist` itself failed. Everything it would have
    written is already lost, so this writes the minimum that keeps the run
    row honest. If the database is unreachable even for this, nothing can be
    recorded -- that is the one case this module cannot cover.
    """
    try:
        async with get_session_factory()() as db:
            run = await db.get(EvaluationRun, run_id)
            if run is None:
                return
            run.status = RunStatus.FAILED
            run.finished_at = datetime.now(timezone.utc)
            await db.commit()
    except Exception:
        logger.exception("could not mark run %s terminal", run_id)


def _stale_run_cutoff() -> datetime:
    """The instant before which a RUNNING row cannot still be in progress.

    Derived from the bounds a run is actually subject to, rather than picked:
    the capture drain, the nmap timeout, the agent's own time budget, the
    chain ingest deadline and the evaluator's worst case, plus a margin for
    everything unbounded but short (three database round trips, the reset and
    the two fingerprints). Over-estimating is the safe direction -- it only
    delays reconciliation -- while under-estimating would terminate a live
    run's row underneath it.
    """
    settings = get_settings()
    longest_possible_run = (
        settings.evaluation_capture_timeout_seconds
        + settings.evaluation_nmap_timeout_seconds
        + settings.evaluation_agent_max_seconds
        + chain_runner.CHAIN_INGEST_TIMEOUT_SECONDS
        + _EVALUATOR_WORST_CASE_SECONDS
        + STALE_RUN_MARGIN_SECONDS
    )
    return datetime.now(timezone.utc) - timedelta(seconds=longest_possible_run)


_AGE_BASED_DETAIL = (
    "still marked running long after any run can take; the process "
    "that started it never finished it, so the row was reconciled as "
    "failed. Nothing was measured -- this is not a result about the "
    "honeypot."
)

_STARTUP_DETAIL = (
    "still marked running when this process started, so no run could "
    "have been in progress; the process that started it never finished "
    "it, so the row was reconciled as failed. Nothing was measured -- "
    "this is not a result about the honeypot."
)


async def reconcile_stale_runs(honeypot_id: str | None = None) -> list[uuid.UUID]:
    """Mark RUNNING rows that can no longer be in progress as FAILED.

    `start_run`'s `finally` covers every failure the process survives. It
    cannot cover the process not surviving: killed mid-run, or `_persist` AND
    `_force_terminal` both failing because the database went away. The row is
    then left `status=running, finished_at=NULL` with nothing in the system
    that would ever finish it, `is_running` answers True for that honeypot
    forever, and the honeypot is locked out of evaluation permanently.

    AGE-BASED, and deliberately so: this is the sweep called on the way into
    `start_run`, where a run started by ANOTHER process may genuinely be in
    progress right now. Nothing here can tell a live run's row from an
    orphan except its age, so only rows older than `_stale_run_cutoff()` --
    older than every bound a run is subject to -- are touched. Terminating a
    live run's row underneath it would lose the run it is about to persist.

    At process startup that restriction is unnecessary and actively harmful:
    no run of a process that has only just begun can be live, so a row killed
    two minutes ago is as certainly dead as one killed three days ago, yet
    would survive this sweep and produce a false "already running" 409 for
    the length of the cutoff. That case has its own entry point,
    `reconcile_orphaned_runs_at_startup`; do not lower the cutoff here to
    cover it, because lowering it is exactly what makes the in-`start_run`
    sweep unsafe.

    FAILED, not COMPLETED: the run's modules, probes and scores were never
    persisted, so it established nothing that survived. The reconciliation is
    recorded as an `orchestrator` module row, because `evaluation_runs` has no
    detail column and a status with no explanation is a worse artefact than
    the lockout it replaces.

    Returns the ids it reconciled, so a caller can log or report them.
    """
    return await _reconcile(honeypot_id, _stale_run_cutoff(), _AGE_BASED_DETAIL)


async def reconcile_orphaned_runs_at_startup() -> list[uuid.UUID]:
    """Mark EVERY RUNNING row FAILED, regardless of age. STARTUP ONLY.

    Safe here and nowhere else. `JobQueue` and every run task live only in
    this process's memory (see `app/workers/queue.py`) and this runs before
    the first request is served, so at this instant this process has no run
    in progress and cannot acquire one. A `status=running, finished_at=NULL`
    row is therefore an orphan whatever its age: whichever process wrote it
    is gone, and Postgres has already dropped the advisory lock that process
    held, so the honeypot is free while its row says otherwise.

    That gap is the whole point. The age-based `reconcile_stale_runs` leaves
    a row killed two minutes ago alone for the full cutoff; the next POST for
    that honeypot then takes the advisory lock, finds `is_running` True, and
    is refused with "an evaluation is already running" -- which is false --
    for up to 45 minutes after a restart. Refusing is the safe direction, so
    this was never a correctness hole, but the message is wrong and the
    window is long enough to look like a broken feature.

    Called with no honeypot id on purpose: an orphan blocks the run that
    would otherwise have cleared it, so the sweep cannot be scoped to a
    honeypot somebody has to ask about first.
    """
    return await _reconcile(None, None, _STARTUP_DETAIL)


async def _reconcile(
    honeypot_id: str | None, cutoff: datetime | None, detail: str
) -> list[uuid.UUID]:
    """Reconcile RUNNING rows, optionally narrowed by honeypot and by age.

    `cutoff=None` means "every RUNNING row" and is only ever correct when the
    caller can prove no run is live; see `reconcile_orphaned_runs_at_startup`.
    """
    async with get_session_factory()() as db:
        query = select(EvaluationRun).where(EvaluationRun.status == RunStatus.RUNNING)
        if cutoff is not None:
            query = query.where(EvaluationRun.started_at < cutoff)
        if honeypot_id is not None:
            query = query.where(EvaluationRun.honeypot_id == honeypot_id)
        stale = (await db.execute(query)).scalars().all()
        # Read the ids BEFORE the commit: the session expires its instances
        # there, and touching an attribute afterwards would try to refresh
        # from a session that is already closing.
        reconciled = [run.id for run in stale]

        for run in stale:
            run.status = RunStatus.FAILED
            run.finished_at = datetime.now(timezone.utc)
            db.add(
                _module_row(
                    run.id,
                    "orchestrator",
                    ModuleStatus.ERROR,
                    detail,
                    run.started_at,
                )
            )
        await db.commit()

    for run_id in reconciled:
        logger.warning("reconciled orphaned evaluation run %s as failed", run_id)
    return reconciled


# --- the run ------------------------------------------------------------


async def _execute_run(
    run_id: uuid.UUID,
    honeypot_id: str,
    target: EvaluationTarget,
    budget: AgentBudget,
    collected: _Collected,
    interface: str,
    capture_container: str | None,
) -> None:
    """Run every module, then score and evaluate what they established.

    `interface` and `capture_container` are required and come from the
    resolved target, never from settings. The interface used to default to
    `settings.evaluation_capture_interface` for "callers that predate
    per-honeypot targets" -- there are none, `start_run` is the only caller --
    and the capture's CONTAINER was read from settings even further down, in
    `tcpdump._spawn`, which is how a run against one honeypot came to count
    another's packets. Both now travel the same path as everything else the
    run says it measured.

    Two results are deliberately NOT allowed to depend on this frame finishing
    cleanly, because both are measurements the run really made:

      * tcpdump's drained outcome. `Capture.stop` runs in the context
        manager's own `finally` and sets `.outcome` even while an exception
        propagates past it, so the fact exists whatever went wrong above --
        but recording it AFTER the `async with` meant a propagating exception
        skipped the recording, and the drained fact became neither a module
        row nor an observation.
      * `collected.scores`. `_persist` decides the run's status from what was
        established, and an exception anywhere in this frame -- an `_emit` to
        a dead queue, the capture failing to start, the chain-row build loop
        -- must not erase a real measurement and report it as the honeypot
        having failed.

    Both therefore happen in `_finalize`, called from a `finally`, and neither
    half of it may raise: an exception there would replace the exception
    actually propagating and misreport the cause of the run's failure.
    """
    settings = get_settings()
    by_probe_id = {probe.id: probe.characteristic for probe in probes.load_probes()}
    observations_by_characteristic: dict[str, list[sanity.Observation]] = {}
    all_observations: list[sanity.Observation] = []
    chain_results: list[ChainStepResult] = []
    endpoint = f"{target.host}:{target.port}"
    # Bound before the `async with` so `_finalize` is safe even when
    # `_capture.__aenter__` itself raises (`tcpdump.Capture.start` catches
    # only OSError; anything else propagates and `cap` is never assigned).
    cap: tcpdump.Capture | None = None

    def record(outcome: ModuleOutcome, module_target: str, started: datetime) -> None:
        _record_outcome(
            run_id,
            collected,
            outcome,
            module_target,
            started,
            by_probe_id,
            observations_by_characteristic,
            all_observations,
        )

    def _finalize() -> None:
        """Keep what the run actually established. Must never raise."""
        try:
            # The capture is drained on the way out of the context manager --
            # including while an exception propagates through it -- so
            # tcpdump's fact exists by the time we get here, and recording it
            # here rather than after the `async with` is what stops a
            # propagating exception from dropping it. Recording it before
            # scoring is also what lets it be scored at all.
            if cap is not None and cap.outcome is not None:
                record(
                    cap.outcome,
                    interface,
                    datetime.now(timezone.utc),
                )
        except Exception:
            logger.exception("could not record the capture outcome on run %s", run_id)
        try:
            collected.scores = _score(observations_by_characteristic, chain_results)
            # `attack_possibilities` is OMITTED, not None, when there were no
            # chains (`scoring.py` adds the key only `if chain_results:`).
            # Nothing reads it by name, so its absence stays an absence: no
            # KeyError, and never a 0.0 conjured to fill the gap.
        except Exception:
            # Scoring is a pure function over observations, so a failure here
            # is entirely ours. The probe and chain rows it would have scored
            # are already collected and still persist, and `_run_status` reads
            # them directly, so the run is not reported as the honeypot having
            # established nothing. No score is invented to fill the gap.
            logger.exception("scoring failed on run %s", run_id)

    await _emit(run_id, 0)
    try:
        # `capture_container` may be None -- a generic target is a bare host
        # or a VM and has no sidecar. `tcpdump.capture` handles that itself
        # and yields an outcome of None, so there is one capture seam here
        # rather than two and a ternary to choose between them.
        async with _capture(
            interface, settings.evaluation_capture_timeout_seconds, capture_container
        ) as started_capture:
            cap = started_capture
            # nmap
            started = datetime.now(timezone.utc)
            await _emit(run_id, 1)
            try:
                record(
                    await _run_nmap(
                        target.host,
                        settings.evaluation_nmap_timeout_seconds,
                        target.port,
                    ),
                    target.host,
                    started,
                )
            except Exception as exc:
                logger.exception("nmap stage failed on run %s", run_id)
                collected.modules.append(
                    _module_row(run_id, "nmap", ModuleStatus.ERROR, str(exc), started)
                )

            # agent probes
            started = datetime.now(timezone.utc)
            await _emit(run_id, 2)
            try:
                record(await _run_agent(target, budget), endpoint, started)
            except Exception as exc:
                logger.exception("agent stage failed on run %s", run_id)
                record(
                    ModuleOutcome(
                        module="agent",
                        module_status=ModuleStatus.ERROR,
                        detail=str(exc),
                        observations=_unknown_probe_observations(),
                    ),
                    endpoint,
                    started,
                )

            # chains
            started = datetime.now(timezone.utc)
            await _emit(run_id, 3, probes_executed=len(collected.probe_rows))
            try:
                chain_run = chain_runner.as_chain_run(await _run_chains(target, honeypot_id))
                chain_results = chain_run.results
                collected.modules.append(
                    _module_row(
                        run_id, "chains", chain_run.module_status, chain_run.detail, started
                    )
                )
            except Exception as exc:
                logger.exception("chain stage failed on run %s", run_id)
                collected.modules.append(
                    _module_row(run_id, "chains", ModuleStatus.ERROR, str(exc), started)
                )

            for result in chain_results:
                collected.chain_rows.append(
                    EvaluationChainStep(run_id=run_id, **result.model_dump())
                )

        await _emit(run_id, 4, chain_steps_verified=len(collected.chain_rows))
    finally:
        _finalize()

    _fact_findings(run_id, collected)
    _contradiction_findings(run_id, collected, all_observations)

    await _emit(run_id, 5, characteristics_scored=len(collected.scores))
    await _evaluate(run_id, collected, _build_packages(collected))
    await _emit(run_id, 6, characteristics_evaluated=len(collected.ratings))


_REACHABILITY_TIMEOUT_SECONDS = 5.0


async def _assert_target_reachable(
    target: EvaluationTarget,
    timeout_seconds: float = _REACHABILITY_TIMEOUT_SECONDS,
    hint: str = "",
) -> None:
    """Confirm something is listening where the evaluation target points.

    A TCP connect and nothing more. Whether what answered is really a Cowrie
    is the agent's question and the fingerprint's; making this a protocol
    check would duplicate both and add a second thing to keep in step with
    the honeypot.

    This exists because of one specific, extremely common misconfiguration:
    `evaluation_target_host` defaults to the compose service name `cowrie`,
    which resolves inside the compose network and nowhere else. A backend run
    on the host -- which is how this project is normally developed -- gets a
    name that does not resolve, and before this check that surfaced two
    minutes later as a run in which every fact was `unknown`.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port),
            timeout=timeout_seconds,
        )
    except (TimeoutError, OSError) as exc:
        raise TargetUnreachableError(
            f"nothing accepted a connection at {target.host}:{target.port} "
            f"within {timeout_seconds}s ({exc}). "
            + (
                hint
                or "The compose service name only resolves from inside the "
                "compose network, so set EVALUATION_TARGET_HOST=127.0.0.1 for a "
                "backend running on the host."
            )
        ) from exc

    # The question was answered the moment the connection was accepted;
    # everything from here is tidying up. `wait_closed()` waits on the PEER,
    # so a target that holds the socket open -- which a real SSH server
    # politely does -- can block here indefinitely. Bounding it keeps a
    # precondition from becoming the hang it exists to prevent.
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout_seconds)
    except (TimeoutError, OSError):
        pass


async def start_run(
    honeypot_id: str,
    run_id: uuid.UUID | None = None,
    actor: Actor | None = None,
) -> uuid.UUID:
    """Run one evaluation end to end and return its id.

    Raises before any row exists when the preconditions fail -- see the module
    docstring for why reset and the fingerprints abort rather than degrade.
    After the row exists, this never raises: every stage failure is recorded
    and the run always reaches a terminal status.

    `actor` records WHO started this. A run resets a honeypot's container
    and executes attack chains, so the record should be able to answer
    that. Omitting it stores `unrecorded` -- the value the migration
    reserves for runs from before the column existed -- which is correct
    only for a caller that genuinely predates the audit trail. Every real
    caller passes one, including the unauthenticated case, which has its
    own distinct value rather than sharing this one. See `Actor`.

    `run_id` lets the CALLER allocate the id. `POST /api/evaluations`
    dispatches this to the background and must return the id immediately,
    but progress is published under `evaluation_job_key(run_id)` -- an id
    minted here and returned only after every stage finished would be a
    channel key no client could subscribe to until the work was already over.
    Omitting it keeps the original behaviour: an id is generated here.
    """
    settings = get_settings()
    # Built from settings ONLY. There must be no code path from an HTTP
    # request to an arbitrary host, or the agent becomes an attack tool. The
    # honeypot id selects among targets an operator configured; it never
    # supplies one.
    configured = targets.resolve(honeypot_id, settings)
    target = EvaluationTarget(
        host=configured.host,
        port=configured.ssh_port,
        username=configured.ssh_username,
        password=configured.ssh_password,
        kind=configured.kind,
    )
    budget = AgentBudget(
        max_commands=settings.evaluation_agent_max_commands,
        max_seconds=settings.evaluation_agent_max_seconds,
    )
    container = configured.container_name

    # A crashed run leaves `status=running` with nothing left in the system to
    # clear it, and `is_running` would then answer True for this honeypot
    # forever. Sweep those first so a crash cannot lock the honeypot out. Only
    # rows too old to still be in progress are touched, so a genuinely
    # concurrent run is never disturbed -- and this is deliberately NOT an
    # admission check: enforcing one-run-at-a-time (the TOCTOU between
    # `is_running` and the INSERT, and the 409) is Task 15's job at the API
    # layer. This only makes sure the flag it reads can ever be cleared.
    await reconcile_stale_runs(honeypot_id)

    # --- preconditions. No run row can exist before all of these succeed. ---
    #
    # Reachability goes FIRST, ahead of the reset, and the order is load
    # bearing: the reset clears the state a previous evaluation left behind.
    # Running it and only then discovering the target was never reachable
    # destroys the previous run's residue to produce nothing at all. The
    # check that costs a TCP connect precedes the one with a side effect.
    await _assert_target_reachable(
        target,
        hint=(
            f"This address came from EVALUATION_TARGETS[{honeypot_id!r}]."
            if settings.evaluation_targets
            else ""
        ),
    )
    if configured.kind == "cowrie":
        await _reset_target(container)
    else:
        # Nothing to clear, rather than "we gave up on clearing".
        #
        # Reset exists because a previous run leaves residue -- downloaded
        # files and tty recordings -- and run B must not observe run A's
        # leftovers. Every one of those artefacts is created by a chain step,
        # and `_run_chains` refuses to execute a destructive chain against a
        # target that does not simulate commands. A run that writes nothing
        # leaves nothing behind, so the precondition holds by construction
        # here instead of by deletion.
        #
        # This is load-bearing on that refusal. If a destructive chain ever
        # becomes runnable against a generic target, this branch is wrong and
        # comparability across two such runs is gone, silently -- there is no
        # `docker exec` into a bare host to clear anything with.
        logger.info(
            "run for honeypot %s targets kind=%s: skipping container reset, "
            "which has nothing to clear because no chain with side effects runs there",
            honeypot_id,
            configured.kind,
        )
    # The password is deliberately not carried across: it does not change
    # what the honeypot is, and this value is hashed into a digest that gets
    # stored and displayed. See `fingerprints.Target`.
    honeypot_fp = await _honeypot_fingerprint(
        fingerprints.Target(
            kind=configured.kind,
            container_name=container,
            host=target.host,
            ssh_port=target.port,
            ssh_username=target.username,
        )
    )
    config_fp = _evaluation_config_fingerprint(
        budget,
        fingerprints.Apparatus(
            capture_interface=configured.capture_interface,
            capture_container=configured.capture_container,
            nmap_timeout_seconds=settings.evaluation_nmap_timeout_seconds,
            capture_timeout_seconds=settings.evaluation_capture_timeout_seconds,
        ),
    )

    if run_id is None:
        run_id = uuid.uuid4()
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                honeypot_id=honeypot_id,
                status=RunStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
                agent_model=_agent_model(),
                evaluator_model=None,
                evaluator_status=EvaluatorStatus.UNAVAILABLE,
                honeypot_fingerprint=honeypot_fp,
                evaluation_config_fingerprint=config_fp,
                started_by=(actor or Actor.unrecorded()).key,
                started_by_label=(actor or Actor.unrecorded()).label,
            )
        )
        await db.commit()

    collected = _Collected()
    try:
        await _execute_run(
            run_id,
            honeypot_id,
            target,
            budget,
            collected,
            interface=configured.capture_interface,
            capture_container=configured.capture_container,
        )
    except Exception:
        # Everything already collected is still persisted below. A stage
        # exploding is our failure, not the honeypot's, so it never becomes a
        # score -- it becomes an absent or `unknown` fact.
        logger.exception("evaluation run %s did not complete cleanly", run_id)
    finally:
        try:
            await _persist(run_id, collected)
        except Exception:
            logger.exception("could not persist evaluation run %s", run_id)
            await _force_terminal(run_id)

    return run_id


# --- read side ----------------------------------------------------------


async def delete_run(run_id: uuid.UUID) -> None:
    """Remove a run and every child, depth-first, in ONE transaction.

    No foreign key in the evaluation schema declares `ondelete`, so the order
    is entirely this function's responsibility and deleting the run row first
    simply raises. `evaluation_evidence` goes first because it points at
    findings AND at chain steps AND at probe results.

    Evidence is never deleted on its own. The deferred trigger only fires on
    finding INSERT, so removing evidence alone would strand a finding with
    nothing grounding it; removing both together, here, is the mitigation for
    that known gap.
    """
    async with get_session_factory()() as db:
        finding_ids = select(EvaluationFinding.id).where(EvaluationFinding.run_id == run_id)
        await db.execute(
            delete(EvaluationEvidence).where(EvaluationEvidence.finding_id.in_(finding_ids))
        )
        await db.execute(delete(EvaluationFinding).where(EvaluationFinding.run_id == run_id))
        await db.execute(delete(EvaluationChainStep).where(EvaluationChainStep.run_id == run_id))
        await db.execute(
            delete(EvaluationProbeResult).where(EvaluationProbeResult.run_id == run_id)
        )
        await db.execute(
            delete(EvaluationModuleResult).where(EvaluationModuleResult.run_id == run_id)
        )
        await db.execute(
            delete(EvaluationCategoryScore).where(EvaluationCategoryScore.run_id == run_id)
        )
        await db.execute(delete(EvaluationRun).where(EvaluationRun.id == run_id))
        await db.commit()


# --- read side and comparison, re-exported ------------------------------
#
# These moved to `read.py` and `comparison.py` -- see this module's docstring.
# They are re-exported because `runs.load_run` and `runs.compare_runs` are the
# names the routers and the test suite already use, and a rename would be
# churn for no gain. Nothing here is a test seam: the suite patches only
# orchestration-side names, which stayed put, so patching still reaches the
# code that calls them.

from app.services.evaluation.comparison import compare_runs
from app.services.evaluation.read import (
    is_running,
    list_run_summaries,
    list_runs,
    load_run,
)
