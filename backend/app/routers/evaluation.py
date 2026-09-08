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

import hashlib
import logging
import uuid

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.db.session import get_engine
from app.models.evaluation import (
    EVALUATION_FAILED_STAGE,
    EVALUATION_FAILED_STAGE_INDEX,
    EvaluationProgressEvent,
    EvaluationRunOut,
    EvaluationRunSummary,
    RunComparison,
    StartEvaluationRequest,
    StartEvaluationResponse,
)
from app.services.dashboard import list_honeypots
from app.services.evaluation import runs
from app.workers.queue import evaluation_job_key, get_queue

logger = logging.getLogger(__name__)

router = APIRouter()

# A history page renders rows; it does not need the whole table. The default
# is what a first screen shows and the ceiling is what one response may ever
# carry, enforced by FastAPI rather than trusted to the caller.
DEFAULT_RUN_LIMIT = 20
MAX_RUN_LIMIT = 100

_LOCK_NAMESPACE = b"hivemind.evaluation.run:"


def _lock_key(honeypot_id: str) -> int:
    """A stable signed 64-bit advisory-lock key for one honeypot.

    `pg_try_advisory_lock` takes a bigint, and honeypot ids are strings, so
    the id is hashed rather than mapped through a table. The namespace prefix
    keeps this key space disjoint from any other advisory lock the
    application might take later against the same database.
    """
    digest = hashlib.sha256(_LOCK_NAMESPACE + honeypot_id.encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


async def _acquire_run_lock(honeypot_id: str) -> AsyncConnection | None:
    """Take the honeypot's run lock, or return None if it is already held.

    Why an advisory lock and not the `is_running` SELECT: that check is a
    TOCTOU with nothing behind it. Two concurrent POSTs both read "not
    running" -- and, because the run row is not inserted until after the
    reset and both fingerprints, they stay both-false for seconds -- so both
    dispatch, both reset the same directory (one then raises a spurious
    FileNotFoundError) and both run chains into overlapping windows. A
    partial unique index on `(honeypot_id) WHERE status = 'running'` would
    also close it, but needs a migration AND still could not cover the gap
    before the row exists.

    Session-scoped, not `pg_advisory_xact_lock`: the lock must be held from
    admission until the run finishes, which spans many pooled sessions and
    minutes of work, so it is pinned to one connection held for the run's
    lifetime and released in `_release_run_lock`. Postgres drops a session
    lock when its connection dies, so a killed process cannot leave the
    honeypot locked out -- unlike a status column, which needs
    `reconcile_stale_runs` to clear it.

    `commit()` after acquiring so the connection sits idle rather than idle
    in transaction for the whole run; a session-level advisory lock is not
    released by a commit.
    """
    connection = await get_engine().connect()
    try:
        held = (
            await connection.execute(
                text("SELECT pg_try_advisory_lock(:key)"), {"key": _lock_key(honeypot_id)}
            )
        ).scalar()
        await connection.commit()
    except BaseException:
        await connection.close()
        raise
    if not held:
        await connection.close()
        return None
    return connection


async def _release_run_lock(connection: AsyncConnection, honeypot_id: str) -> None:
    """Release the lock explicitly, then return the connection to the pool.

    Closing alone is NOT enough: the pool hands the same DBAPI connection out
    again after a rollback, and a rollback does not release a session-level
    advisory lock. Skipping the unlock would leak the lock onto an unrelated
    later caller and 409 that honeypot until the process restarts.
    """
    try:
        await connection.execute(
            text("SELECT pg_advisory_unlock(:key)"), {"key": _lock_key(honeypot_id)}
        )
        await connection.commit()
    except Exception:  # noqa: BLE001 - the run is over; never mask its outcome
        logger.exception("could not release the evaluation lock for honeypot %s", honeypot_id)
    finally:
        await connection.close()


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


async def _dispatch(run_id: uuid.UUID, honeypot_id: str, lock: AsyncConnection) -> None:
    """Run the evaluation, then release the honeypot's lock, always.

    `start_run` never raises once its run row exists, so an exception here
    means the run never started; it is logged and published as a terminal
    event. The `finally` covers cancellation too -- a lock held by a task
    nobody cancels cleanly would 409 the honeypot for the process's life.
    """
    try:
        await runs.start_run(honeypot_id, run_id=run_id)
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        logger.exception("evaluation run %s never started", run_id)
        await _publish_start_failure(run_id, exc)
    finally:
        await _release_run_lock(lock, honeypot_id)


@router.post("/evaluations", response_model=StartEvaluationResponse, status_code=202)
async def start_evaluation(request: StartEvaluationRequest) -> StartEvaluationResponse:
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
    known = {honeypot.id for honeypot in await list_honeypots()}
    if request.honeypot_id not in known:
        raise HTTPException(status_code=404, detail=f"unknown honeypot {request.honeypot_id}")

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
    get_queue().enqueue(
        evaluation_job_key(str(run_id)), _dispatch(run_id, request.honeypot_id, lock)
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


@router.websocket("/evaluations/{run_id}/progress")
async def progress(websocket: WebSocket, run_id: str) -> None:
    """Live stages for a run, from the moment this connects.

    No history and no replay -- see `JobQueue.subscribe`. Events published
    between the POST's 202 and this subscription are gone, and a client that
    connects after the run finished receives nothing and waits: there is no
    buffered backlog and no "already completed" frame. Read the outcome back
    from `GET /api/evaluations/{run_id}` instead of relying on this stream.

    One terminal frame is possible without any stage frames before it:
    `stage == "failed"` with an `error`, meaning the run aborted before its
    row existed and nothing will follow.
    """
    await websocket.accept()
    try:
        async for event in get_queue().subscribe(evaluation_job_key(run_id)):
            await websocket.send_json(event.model_dump(by_alias=True))
    except WebSocketDisconnect:
        return
