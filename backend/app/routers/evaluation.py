"""HTTP and WebSocket surface for honeypot-realism evaluation runs.

Three properties of this module are load-bearing and none may be relaxed for
convenience.

**Containment.** There is no code path from an HTTP request to an arbitrary
host or command. `StartEvaluationRequest` carries a honeypot id and nothing
else -- no host, no port, no address, and `extra="forbid"` so none can be
smuggled in -- the id must resolve through the honeypot registry, and the
target `start_run` connects to is built from settings alone. Widen any of
those three and the agent becomes an attack tool.

**Two assessments are never combined.** `deterministic_score` and
`evaluator_rating` answer different questions and are passed straight through
in two fields. `None` means "not established" and is never rendered as 0 or
dropped from a payload -- including `RunComparison.deltas`, where a `None`
entry means "unknown on one side", which is not the same as no delta.

**One run at a time per honeypot.** Two overlapping runs reset the same
container underneath each other and interleave their traffic into each
other's chain read-back windows, which is the evidence mis-attribution Task
14 fixed. `runs.is_running` is a bare SELECT with no constraint behind it, so
the guard here is a Postgres advisory lock held for the run's lifetime; see
`_acquire_run_lock`.

**The POST does not wait for the run.** It allocates the run id, returns 202,
and dispatches. `start_run` awaits a container reset, an nmap scan, the
agent's 120s budget, a 30s chain-ingest poll and one LLM call per
characteristic; a synchronous POST would simply time out. More importantly
the id must reach the client BEFORE the run publishes anything, because
progress goes out under `evaluation_job_key(run_id)` and `JobQueue.subscribe`
has no replay -- an id returned only after every stage finished would be a
channel key nobody could ever use in time. The client flow is: POST, take the
id, open the WebSocket, receive stages.
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket
from sqlalchemy.ext.asyncio import AsyncConnection

from app.auth import Actor, assert_admin_for, require_admin
from app.db import locks
from app.models.evaluation import (
    EVALUATION_FAILED_STAGE,
    EVALUATION_FAILED_STAGE_INDEX,
    EvaluationProgressEvent,
    EvaluationRunOut,
    EvaluationRunSummary,
    RunComparison,
    ConfigSettingOut,
    HoneyfsFileOut,
    RemediationOut,
    StartEvaluationRequest,
    StartEvaluationResponse,
)
from app.config import get_settings
from app.services.dashboard import list_honeypots
from app.services.evaluation import remediation, runs, targets
from app.workers.queue import evaluation_job_key, get_queue, stream_progress

logger = logging.getLogger(__name__)

router = APIRouter()

# A history page renders rows; it does not need the whole table. The default
# is what a first screen shows and the ceiling is what one response may ever
# carry, enforced by FastAPI rather than trusted to the caller.
DEFAULT_RUN_LIMIT = 20
MAX_RUN_LIMIT = 100

# Keeps this key space disjoint from every other advisory lock the
# application takes -- see `app.db.locks.lock_key`.
_LOCK_NAMESPACE = b"hivemind.evaluation.run:"


async def _acquire_run_lock(honeypot_id: str) -> AsyncConnection | None:
    """Take the honeypot's run lock, or return None if it is already held.

    Why a lock and not the `is_running` SELECT: that check is a TOCTOU with
    nothing behind it. Two concurrent POSTs both read "not running" -- and,
    because the run row is not inserted until after the reset and both
    fingerprints, they stay both-false for seconds -- so both dispatch, both
    reset the same directory (one then raises a spurious FileNotFoundError)
    and both run chains into overlapping windows.

    Acquired here and released in `_dispatch`, which is why this uses the
    `acquire`/`release` primitives rather than `locks.held`: the lock outlives
    the request that took it.
    """
    return await locks.acquire(_LOCK_NAMESPACE, honeypot_id)


async def _release_run_lock(connection: AsyncConnection, honeypot_id: str) -> None:
    return await locks.release(connection, _LOCK_NAMESPACE, honeypot_id)


async def _publish_start_failure(run_id: uuid.UUID, exc: BaseException) -> None:
    """Say on the run's own channel that the run never started.

    `start_run` raises before any row exists when the reset or either
    fingerprint fails -- `ResetError`, `ResetBoundaryError` (a ValueError,
    NOT a ResetError) or `fingerprints.FingerprintError`. Dispatched to the
    background, that exception reaches no HTTP caller: without this,
    `GET /evaluations/{id}` 404s with no explanation and a subscriber waits
    forever for a run that will never publish. Our own failure is reported,
    never hidden.
    """
    try:
        await get_queue().publish(
            evaluation_job_key(str(run_id)),
            EvaluationProgressEvent(
                stage_index=EVALUATION_FAILED_STAGE_INDEX,
                stage=EVALUATION_FAILED_STAGE,
                error=f"{type(exc).__name__}: {exc}",
            ),
        )
    except Exception:  # noqa: BLE001 - already handling a failure
        logger.exception("could not publish the start failure for run %s", run_id)


async def _dispatch(
    run_id: uuid.UUID, honeypot_id: str, lock: AsyncConnection, actor: Actor
) -> None:
    """Run the evaluation, then release the honeypot's lock, always.

    `start_run` never raises once its run row exists, so an exception here
    means the run never started; it is logged and published as a terminal
    event. The `finally` covers cancellation too -- a lock held by a task
    nobody cancels cleanly would 409 the honeypot for the process's life.
    """
    try:
        await runs.start_run(honeypot_id, run_id=run_id, actor=actor)
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        logger.exception("evaluation run %s never started", run_id)
        await _publish_start_failure(run_id, exc)
    finally:
        await _release_run_lock(lock, honeypot_id)


# admin, and this is the one that matters most: a run RESETS the honeypot's
# container and executes attack chains against it. See `analyze` for why
# the dependency sits on the parameter.
@router.post("/evaluations", response_model=StartEvaluationResponse, status_code=202)
async def start_evaluation(
    request: StartEvaluationRequest,
    claims: dict | None = Depends(require_admin),
) -> StartEvaluationResponse:
    """Accept a run and dispatch it. 202, not 200: it has not happened yet.

    404 when the honeypot id is not in the registry -- the only thing the
    body may name, and the only way a target is chosen. 409 when a run is
    already in progress for that honeypot.

    The returned id is the progress channel's key. Because
    `JobQueue.subscribe` has no history or replay, any event published
    between this response and the client's subscription is LOST: the channel
    is a live view, and `GET /api/evaluations/{run_id}` is the authoritative
    record of what the run established.
    """
    # The registry is derived from indexed events -- a honeypot exists because
    # its events do -- so a freshly built comparison target has captured
    # nothing yet and would be refused here. A configured evaluation target is
    # equally good proof that the honeypot exists, and is just as server-side,
    # so either admits the id. Containment is unchanged: both sets are
    # operator-controlled, and neither comes from the request.
    # The specific half of the gate. `require_admin` already refused a caller
    # who is admin nowhere; this refuses one who is admin somewhere else.
    # Before the registry lookup, so a viewer on this honeypot cannot use the
    # 404 to learn which honeypot ids exist.
    assert_admin_for(claims, request.honeypot_id)

    known = {honeypot.id for honeypot in await list_honeypots()}
    known |= set(get_settings().evaluation_targets)
    if request.honeypot_id not in known:
        raise HTTPException(status_code=404, detail=f"unknown honeypot {request.honeypot_id}")

    # An id can be in the event-derived registry and still have no configured
    # target once a map exists. Resolving here turns that into a 404 the
    # caller can read, instead of a run that is accepted, dispatched, and then
    # dies in the background with nothing but a terminal socket frame.
    try:
        targets.resolve(request.honeypot_id, get_settings())
    except targets.UnknownTargetError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    # Clear anything a killed process orphaned before reading the flag, so a
    # crash cannot 409 this honeypot forever. Only rows too old to still be
    # in progress are touched.
    await runs.reconcile_stale_runs(request.honeypot_id)

    lock = await _acquire_run_lock(request.honeypot_id)
    if lock is None:
        raise HTTPException(
            status_code=409,
            detail=f"an evaluation is already running for honeypot {request.honeypot_id}",
        )
    try:
        # Belt and braces: the lock stops a concurrent request in THIS
        # process, and this stops a row another process left RUNNING and too
        # recent to reconcile. Refusing is the safe direction -- admitting a
        # run alongside a live one corrupts both runs' evidence.
        if await runs.is_running(request.honeypot_id):
            raise HTTPException(
                status_code=409,
                detail=f"an evaluation is already running for honeypot {request.honeypot_id}",
            )
    except BaseException:
        await _release_run_lock(lock, request.honeypot_id)
        raise

    # Allocated HERE, not inside `start_run`, so the client holds the channel
    # key before the run can publish on it.
    run_id = uuid.uuid4()
    # The verified claims come from the dependency that already gated this
    # route, so the recorded actor is the one the token proved -- never a
    # value the caller supplied. A request body cannot name who it is.
    get_queue().enqueue(
        evaluation_job_key(str(run_id)),
        _dispatch(run_id, request.honeypot_id, lock, Actor.from_claims(claims)),
    )
    return StartEvaluationResponse(run_id=str(run_id))


@router.get("/evaluations", response_model=list[EvaluationRunSummary])
async def get_evaluations(
    limit: int = Query(DEFAULT_RUN_LIMIT, ge=1, le=MAX_RUN_LIMIT),
) -> list[EvaluationRunSummary]:
    """Bounded history rows. Deliberately NOT `list[EvaluationRunOut]`.

    Each `EvaluationRunOut` carries every probe result, finding, evidence row
    and chain step of its run, hydrated with ~7 queries; a list of them would
    transfer the entire evaluation database to draw a table. Read one run in
    full through `GET /api/evaluations/{run_id}`.
    """
    return await runs.list_run_summaries(limit)


# `/evaluations/compare` MUST be declared before `/evaluations/{run_id}`.
# FastAPI matches in declaration order, so the other way round "compare" is
# parsed as a run id and this route is unreachable.
@router.get("/evaluations/compare", response_model=RunComparison)
async def compare_evaluations(base: uuid.UUID, head: uuid.UUID) -> RunComparison:
    """Delta between two runs. Never refused, and never a composite.

    `compare_runs` RAISES `RunNotFoundError` (a LookupError) for an unknown
    id -- it never returns None -- so the 404 has to come from catching it.
    `deltas[c] is None` means "not established on one side or the other" and
    is carried as a null: it is neither 0 nor an omitted key.
    """
    try:
        return await runs.compare_runs(base, head)
    except runs.RunNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"unknown evaluation run {exc}") from exc


@router.get("/evaluations/{run_id}", response_model=EvaluationRunOut)
async def get_evaluation(run_id: uuid.UUID) -> EvaluationRunOut:
    """One run in full, and the authoritative record of it.

    A run whose `status` is `failed` while every module is `completed` is a
    real state -- our own orchestration failed after the modules measured
    what they measured -- and is served as it is stored, not relabelled.
    """
    run = await runs.load_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"unknown evaluation run {run_id}")
    return run


@router.get(
    "/evaluations/{run_id}/remediation", response_model=list[RemediationOut]
)
async def get_evaluation_remediation(run_id: uuid.UUID) -> list[RemediationOut]:
    """How to fix what this run found, finding by finding.

    A read, not an action: this computes a patch and returns it, and nothing
    here touches the honeypot. Applying a remediation is the operator's
    deliberate act -- writing files into a honeyfs directory and restarting
    the decoy -- which is why this is a GET and needs no admin role even
    though starting the run that produced the findings does.

    Every finding gets an entry, including the ones with no mechanical fix,
    which carry `unsupportedReason` and no patch. See `remediation.py` for
    why that refusal is the point rather than a gap.
    """
    run = await runs.load_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"unknown evaluation run {run_id}")
    return [
        RemediationOut(
            finding_key=item.finding_key,
            summary=item.summary,
            honeyfs_files=[
                HoneyfsFileOut(path=f.path, content=f.content)
                for f in item.honeyfs_files
            ],
            config_settings=[
                ConfigSettingOut(section=s.section, option=s.option, value=s.value)
                for s in item.config_settings
            ],
            unsupported_reason=item.unsupported_reason,
            from_template=item.from_template,
            is_actionable=item.is_actionable,
        )
        for item in remediation.remediate(run)
    ]


@router.websocket("/evaluations/{run_id}/progress")
async def progress(websocket: WebSocket, run_id: uuid.UUID) -> None:
    """Live stages for a run, from the moment this connects.

    No history and no replay -- see `JobQueue.subscribe`. Events published
    between the POST's 202 and this subscription are gone, and a client that
    connects after the run finished receives nothing and waits: there is no
    buffered backlog and no "already completed" frame. Read the outcome back
    from `GET /api/evaluations/{run_id}` instead of relying on this stream.

    One terminal frame is possible without any stage frames before it:
    `stage == "failed"` with an `error`, meaning the run aborted before its
    row existed and nothing will follow.

    `uuid.UUID` and not `str`, matching `GET /api/evaluations/{run_id}`.
    Publishers key on `str(run_id)`, which is canonical lowercase, so a raw
    string parameter meant the uppercase or braced spelling of an id -- which
    the GET accepts and normalises -- opened a channel nobody publishes on:
    the socket connected, was accepted, and then silently received nothing
    forever, with no error and no close frame. Parsing here normalises both
    routes to the same channel, and rejects an id that is not one at all
    rather than allocating it a channel of its own.
    """
    await stream_progress(websocket, evaluation_job_key(str(run_id)))
