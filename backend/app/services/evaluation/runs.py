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
"""

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel
from sqlalchemy import delete, select

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
    EvidenceKind,
    FactStatus,
    ModuleStatus,
    RunStatus,
)
from app.db.session import get_session_factory
from app.es.client import get_es
from app.models.evaluation import (
    EVALUATION_STAGES,
    CategoryScoreOut,
    ChainStepOut,
    EvaluationProgressEvent,
    EvaluationRunOut,
    EvidenceOut,
    FindingOut,
    LiveEvaluationMetrics,
    ModuleResultOut,
    ProbeResultOut,
    RunComparison,
)
from app.services.chunking import MAX_ITEM_CHARS, truncate_text
from app.services.compaction import CompactedCommand
from app.services.evaluation import agent as agent_module
from app.services.evaluation import fingerprints, probes, sanity, scoring
from app.services.evaluation.agent import AgentBudget, EvaluationTarget
from app.services.evaluation.evaluator import EvidenceItem, evaluate_characteristic
from app.services.evaluation.outcomes import ModuleOutcome
from app.services.evaluation.reset import ResetBoundaryError, ResetError, reset_target
from app.services.evaluation.static import chains as chains_module
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
    "list_runs",
    "load_run",
    "start_run",
]

# `EvaluationModuleResult.detail` and every other stored error string is
# bounded here, matching `container.ERROR_DETAIL_LIMIT` and
# `evaluator._DETAIL_LIMIT`. A `ResetError`/`ContainerExecError` message is
# already bounded upstream; an arbitrary exception's str() is not.
DETAIL_LIMIT = 500

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

# --- chain read-back ---------------------------------------------------
#
# Reset deliberately PRESERVES cowrie.json (it is the source of every session
# this whole system analyses), and does not restart Cowrie. So the log still
# holds run A's commands when run B starts, and the read-back must be scoped
# or run B verifies its chains against run A's events.
CHAIN_INGEST_TIMEOUT_SECONDS = 30.0
CHAIN_INGEST_POLL_SECONDS = 1.0
# Cowrie stamps `@timestamp` from the container's clock and Filebeat ships
# asynchronously. The window is widened by this much on both sides so a small
# clock offset cannot drop a command that really was executed -- being
# narrow here would blame the honeypot for our own skew. Over-inclusion is
# then closed off separately: only commands whose text is one of the chain's
# own declared steps are fed to `verify_chain`.
CHAIN_CLOCK_SKEW_SECONDS = 5


class RunNotFoundError(LookupError):
    """No evaluation run with that id."""


class ChainRun(BaseModel):
    """Chain results plus how the chain stage itself went.

    `_run_chains` may also return a bare `list[ChainStepResult]`; see
    `_as_chain_run`. Two shapes are accepted because the stage has to report
    an ingest timeout (which is OUR failure, not the honeypot's) without
    forcing every caller and stub to construct a wrapper.
    """

    results: list[ChainStepResult] = []
    module_status: str = ModuleStatus.COMPLETED
    detail: str | None = None


@dataclass
class PendingFinding:
    """A finding and the evidence that grounds it, kept together.

    Migration `ad6b0d86d035` installs a CONSTRAINT TRIGGER ... DEFERRABLE
    INITIALLY DEFERRED that rejects any `evaluation_findings` row reaching
    COMMIT with no `evaluation_evidence`. It fires at COMMIT, not at INSERT,
    so a finding and its evidence must be written in ONE transaction. Pairing
    them in one object is what makes "commit a finding, then add evidence"
    unrepresentable in this module.
    """

    finding: EvaluationFinding
    evidence: list[EvaluationEvidence]


@dataclass
class _Collected:
    """Everything gathered so far, so a `finally` can persist a partial run."""

    modules: list[EvaluationModuleResult] = field(default_factory=list)
    probe_rows: list[EvaluationProbeResult] = field(default_factory=list)
    chain_rows: list[EvaluationChainStep] = field(default_factory=list)
    scores: dict[str, float | None] = field(default_factory=dict)
    ratings: dict[str, float] = field(default_factory=dict)
    findings: list[PendingFinding] = field(default_factory=list)
    evaluator_status: str = EvaluatorStatus.UNAVAILABLE
    evaluator_model: str | None = None
    # probe row id -> the characteristic it belongs to, so evidence packages
    # can be assembled per characteristic without a second pass over probes.
    characteristic_by_probe_row: dict[uuid.UUID, str] = field(default_factory=dict)


# --- seams -------------------------------------------------------------
#
# Thin module-level indirections so tests can replace EVERY subprocess and SSH
# boundary. No test may open a real SSH connection, run docker, run nmap or
# run tcpdump: those all touch the live honeypot, which holds real captured
# session data.

_reset_target = reset_target
_honeypot_fingerprint = fingerprints.honeypot_fingerprint
_evaluation_config_fingerprint = fingerprints.evaluation_config_fingerprint
_capture = tcpdump.capture
_score = scoring.score_characteristics


class _NoCapture:
    """Stands in for a `tcpdump.Capture` that was never started."""

    outcome: ModuleOutcome | None = None


@asynccontextmanager
async def _null_capture(interface: str, timeout_seconds: int):
    """A capture that captures nothing and claims nothing.

    `outcome is None` is deliberately NOT an `unknown` tcpdump fact: a run
    with no capture at all made no claim about network activity, which is
    different from having looked and failed. Nothing is persisted for it.
    """
    yield _NoCapture()


def _evaluator_client() -> LLMClient | None:
    """The BYOK evaluator, or None. NEVER the local model.

    `llm.get_evaluator_client()` falls back to Ollama; that is right for
    session analysis and wrong here. The source paper measured sub-70b models
    as returning "only superficial results" for the realism-judgement role,
    and a shallow-but-plausible realism verdict is the exact failure this
    system exists to prevent. No key means `evaluator_status=UNAVAILABLE`,
    reported as such, with the deterministic measurement fully intact.
    """
    settings = get_settings()
    if settings.byok_api_key and settings.byok_provider and settings.byok_model:
        return ByokClient(settings.byok_provider, settings.byok_api_key, settings.byok_model)
    return None


async def _run_nmap(target: str, timeout_seconds: int) -> ModuleOutcome:
    return await nmap_module.scan(target, timeout_seconds)


async def _run_agent(target: EvaluationTarget, budget: AgentBudget) -> ModuleOutcome:
    return await agent_module.run_probes(target, budget)


async def _run_chains(target: EvaluationTarget, honeypot_id: str) -> ChainRun:
    """Execute the predefined chains, then verify them from Cowrie's own log.

    Chains are fixed ids from `chains.yaml`, never caller-supplied command
    sequences: `EvaluationTarget` is built from settings only, so there is no
    path from an HTTP request to an arbitrary command against an arbitrary
    host.

    The SSH primitives come from `agent`'s own seams so chain execution
    inherits the same bounded exit-status wait a probe gets (Cowrie can leave
    a channel open without ever sending an exit status; see
    `agent.PER_COMMAND_TIMEOUT_SECONDS`).

    A chain is only verified when every one of its steps was found in the
    read-back window. A chain whose commands never arrived is OMITTED, and the
    stage reports TIMEOUT. `verify_chain` hardcodes `not_observed` for a
    missing technique, justified by "the commands WERE executed and the rules
    WERE applied" -- that justification fails when we could not read the log
    at all, and feeding it a partial command list would score our own ingest
    lag as a honeypot defect. Omitting the chain leaves it `unknown` by
    absence, which scoring excludes from both numerator and denominator.
    """
    loaded = chains_module.load_chains()
    if not loaded:
        return ChainRun(results=[], module_status=ModuleStatus.SKIPPED, detail="no chains configured")

    started = datetime.now(timezone.utc)
    async with agent_module._open_session(target) as session:
        for chain in loaded:
            for step in chain.steps:
                await agent_module._execute(session, step)
    finished = datetime.now(timezone.utc)

    wanted = {step for chain in loaded for step in chain.steps}
    found = await _read_back_commands(honeypot_id, started, finished, wanted)

    results: list[ChainStepResult] = []
    incomplete: list[str] = []
    for chain in loaded:
        if any(step not in found for step in chain.steps):
            incomplete.append(chain.id)
            continue
        results.extend(chains_module.verify_chain(chain, [found[step] for step in chain.steps]))

    if incomplete:
        return ChainRun(
            results=results,
            module_status=ModuleStatus.TIMEOUT,
            detail=(
                f"commands for chain(s) {', '.join(incomplete)} were not indexed within "
                f"{CHAIN_INGEST_TIMEOUT_SECONDS}s; those chains were left unverified rather "
                f"than scored as absent"
            ),
        )
    return ChainRun(results=results, module_status=ModuleStatus.COMPLETED)


async def _search_commands(honeypot_id: str, start: datetime, end: datetime) -> list[dict]:
    """Cowrie command events for ONE honeypot inside ONE time window.

    Every filter here is load-bearing:

      * `honeypot.id` -- another sensor's traffic is not this run's.
      * `labels.seeded: false` -- the demo corpus is indexed into the same
        index and its synthetic timestamps must never verify a live chain.
      * the `@timestamp` range -- this is what stops run B reading run A's
        commands. Reset preserves cowrie.json by design, so the log is NOT
        empty when a run starts and time is the only thing separating the
        two runs' events.
    """
    settings = get_settings()
    result = await get_es().search(
        index=settings.es_index,
        query={
            "bool": {
                "filter": [
                    {"term": {"honeypot.id": honeypot_id}},
                    {"term": {"event.action": "cowrie.command.input"}},
                    {"term": {"labels.seeded": False}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": _iso(start - timedelta(seconds=CHAIN_CLOCK_SKEW_SECONDS)),
                                "lte": _iso(end + timedelta(seconds=CHAIN_CLOCK_SKEW_SECONDS)),
                            }
                        }
                    },
                ]
            }
        },
        sort=[{"@timestamp": "asc"}],
        size=1000,
    )
    return result["hits"]["hits"]


async def _read_back_commands(
    honeypot_id: str, start: datetime, end: datetime, wanted: set[str]
) -> dict[str, CompactedCommand]:
    """Poll until every wanted command is indexed, or the deadline passes.

    Filebeat tails cowrie.json asynchronously, so a command executed a moment
    ago is not yet searchable. Polling rather than sleeping a fixed interval
    keeps the common case fast and the slow case honest: on timeout the caller
    reports TIMEOUT rather than treating the gap as a honeypot failure.
    """
    deadline = time.monotonic() + CHAIN_INGEST_TIMEOUT_SECONDS
    found: dict[str, CompactedCommand] = {}
    while True:
        for hit in await _search_commands(honeypot_id, start, end):
            source = hit["_source"]
            process = source.get("process") or {}
            command = process.get("command_line")
            # Only the chain's own declared steps. The window is deliberately
            # widened for clock skew, and without this an unrelated command
            # that happened to land inside it could credit the honeypot with a
            # technique its chain never exercised.
            if not command or command not in wanted or command in found:
                continue
            found[command] = CompactedCommand(
                event_id=hit["_id"],
                timestamp=source.get("@timestamp", ""),
                command=command,
                output_excerpt=process.get("output"),
            )
        if len(found) >= len(wanted) or time.monotonic() >= deadline:
            return found
        await asyncio.sleep(CHAIN_INGEST_POLL_SECONDS)


def _as_chain_run(returned: object) -> ChainRun:
    if isinstance(returned, ChainRun):
        return returned
    return ChainRun(results=list(returned or []))


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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


def _bound_package(items: list[EvidenceItem]) -> list[EvidenceItem]:
    """Bound the WHOLE package, not just each item. See MAX_PACKAGE_CHARS."""
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

    What this loses: which characteristics failed, and why. There is no
    `detail` column anywhere in the evaluation schema, so `evaluator_rating
    IS NULL` collapses four distinct outcomes -- no BYOK key, no evidence
    gathered for that characteristic, a provider error, and a verdict
    rejected for citing evidence that was not in its package -- into one
    blank. Each is logged at WARNING with its characteristic and detail; the
    database cannot currently tell them apart.
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
    client = _evaluator_client()
    collected.evaluator_model = client.model_name if client is not None else None

    statuses: list[str] = []
    for characteristic, package in packages.items():
        outcome = await evaluate_characteristic(client, characteristic, package)
        statuses.append(outcome.status)
        if outcome.verdict is None:
            logger.info(
                "evaluator produced no verdict for %s on run %s: %s (%s)",
                characteristic,
                run_id,
                outcome.status,
                outcome.detail,
            )
            continue

        verdict = outcome.verdict
        collected.ratings[characteristic] = verdict.rating
        finding = EvaluationFinding(
            run_id=run_id,
            characteristic=characteristic,
            severity=_severity_for(verdict.rating),
            finding=truncate_text(verdict.critique, MAX_ITEM_CHARS),
            recommendation=_bounded(verdict.recommendation, MAX_ITEM_CHARS),
            source="evaluator",
        )
        evidence = _evidence_for(finding.id, verdict.cited_evidence_ids)
        if not evidence:
            # Every citation resolved to nothing persistable. A finding with
            # no evidence is rejected at COMMIT by design, and writing one
            # would abort the whole transaction -- so it is dropped here,
            # loudly, rather than taking the run's other results with it.
            logger.warning(
                "dropping evaluator finding for %s on run %s: no cited evidence resolved",
                characteristic,
                run_id,
            )
            continue
        collected.findings.append(PendingFinding(finding=finding, evidence=evidence))

    collected.evaluator_status = _aggregate_evaluator_status(statuses)


def _contradiction_findings(
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


def _stage_finding(db, pending: PendingFinding) -> None:
    """Queue one finding plus its evidence on `db`. Nothing is written yet.

    The evidence is parked in the session's own scratch space so it cannot
    be forgotten between the finding's INSERT and the COMMIT the deferred
    trigger checks at.
    """
    db.add(pending.finding)
    db.info.setdefault(_PENDING_EVIDENCE, []).extend(pending.evidence)


async def _flush_findings(db) -> None:
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

    A run is never left RUNNING: `start_run`'s `finally` always writes one of
    these two.
    """
    if any(score is not None for score in collected.scores.values()):
        return RunStatus.COMPLETED
    return RunStatus.FAILED


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
            db.add(
                EvaluationCategoryScore(
                    run_id=run_id,
                    characteristic=characteristic,
                    deterministic_score=score,
                    # None, never 0.0, when the evaluator produced no verdict.
                    evaluator_rating=collected.ratings.get(characteristic),
                )
            )
        # A characteristic the evaluator rated but scoring did not reach still
        # deserves its row -- with deterministic_score None, not 0.0.
        for characteristic, rating in collected.ratings.items():
            if characteristic not in collected.scores:
                db.add(
                    EvaluationCategoryScore(
                        run_id=run_id,
                        characteristic=characteristic,
                        deterministic_score=None,
                        evaluator_rating=rating,
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
    except Exception:  # noqa: BLE001
        logger.exception("could not mark run %s terminal", run_id)


# --- the run ------------------------------------------------------------


async def _execute_run(
    run_id: uuid.UUID,
    honeypot_id: str,
    target: EvaluationTarget,
    budget: AgentBudget,
    collected: _Collected,
) -> None:
    settings = get_settings()
    by_probe_id = {probe.id: probe.characteristic for probe in probes.load_probes()}
    observations_by_characteristic: dict[str, list[sanity.Observation]] = {}
    all_observations: list[sanity.Observation] = []
    chain_results: list[ChainStepResult] = []
    endpoint = f"{target.host}:{target.port}"

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

    await _emit(run_id, 0)
    async with _capture(
        settings.evaluation_capture_interface, settings.evaluation_capture_timeout_seconds
    ) as cap:
        # nmap
        started = datetime.now(timezone.utc)
        await _emit(run_id, 1)
        try:
            record(
                await _run_nmap(target.host, settings.evaluation_nmap_timeout_seconds),
                target.host,
                started,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("nmap stage failed on run %s", run_id)
            collected.modules.append(
                _module_row(run_id, "nmap", ModuleStatus.ERROR, str(exc), started)
            )

        # agent probes
        started = datetime.now(timezone.utc)
        await _emit(run_id, 2)
        try:
            record(await _run_agent(target, budget), endpoint, started)
        except Exception as exc:  # noqa: BLE001
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
            chain_run = _as_chain_run(await _run_chains(target, honeypot_id))
            chain_results = chain_run.results
            collected.modules.append(
                _module_row(
                    run_id, "chains", chain_run.module_status, chain_run.detail, started
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("chain stage failed on run %s", run_id)
            collected.modules.append(
                _module_row(run_id, "chains", ModuleStatus.ERROR, str(exc), started)
            )

        for result in chain_results:
            collected.chain_rows.append(
                EvaluationChainStep(run_id=run_id, **result.model_dump())
            )

    # The capture is drained on the way out of the context manager above --
    # including when a stage raised -- so tcpdump's fact exists by here and
    # can be scored like any other.
    if cap.outcome is not None:
        record(cap.outcome, settings.evaluation_capture_interface, datetime.now(timezone.utc))

    await _emit(run_id, 4, chain_steps_verified=len(collected.chain_rows))
    collected.scores = _score(observations_by_characteristic, chain_results)
    # `attack_possibilities` is OMITTED, not None, when there were no chains
    # (`scoring.py` adds the key only `if chain_results:`). Nothing below
    # reads it by name, so its absence stays an absence: no KeyError, and
    # never a 0.0 conjured to fill the gap.

    _contradiction_findings(run_id, collected, all_observations)

    await _emit(run_id, 5, characteristics_scored=len(collected.scores))
    await _evaluate(run_id, collected, _build_packages(collected))
    await _emit(run_id, 6, characteristics_evaluated=len(collected.ratings))


async def start_run(honeypot_id: str) -> uuid.UUID:
    """Run one evaluation end to end and return its id.

    Raises before any row exists when the preconditions fail -- see the module
    docstring for why reset and the fingerprints abort rather than degrade.
    After the row exists, this never raises: every stage failure is recorded
    and the run always reaches a terminal status.
    """
    settings = get_settings()
    # Built from settings ONLY. There must be no code path from an HTTP
    # request to an arbitrary host, or the agent becomes an attack tool.
    target = EvaluationTarget(
        host=settings.evaluation_target_host,
        port=settings.evaluation_ssh_port,
        username=settings.evaluation_ssh_username,
        password=settings.evaluation_ssh_password,
    )
    budget = AgentBudget(
        max_commands=settings.evaluation_agent_max_commands,
        max_seconds=settings.evaluation_agent_max_seconds,
    )
    container = settings.evaluation_container_name

    # --- preconditions. No run row can exist before all three succeed. ---
    await _reset_target(container)
    honeypot_fp = await _honeypot_fingerprint(container)
    config_fp = _evaluation_config_fingerprint(budget)

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
            )
        )
        await db.commit()

    collected = _Collected()
    try:
        await _execute_run(run_id, honeypot_id, target, budget, collected)
    except Exception:  # noqa: BLE001
        # Everything already collected is still persisted below. A stage
        # exploding is our failure, not the honeypot's, so it never becomes a
        # score -- it becomes an absent or `unknown` fact.
        logger.exception("evaluation run %s did not complete cleanly", run_id)
    finally:
        try:
            await _persist(run_id, collected)
        except Exception:  # noqa: BLE001
            logger.exception("could not persist evaluation run %s", run_id)
            await _force_terminal(run_id)

    return run_id


# --- read side ----------------------------------------------------------


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


async def is_running(honeypot_id: str) -> bool:
    """One run at a time per honeypot (spec §6.2; Task 15 returns 409).

    Concurrent runs interleave their traffic, which makes tcpdump attribution
    and the chain read-back's time window meaningless.
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

    return RunComparison(
        base=base,
        head=head,
        classification="same_configuration" if not differences else "configuration_changed",
        differences=differences,
        deltas=deltas,
    )


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
