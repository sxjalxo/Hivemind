import asyncio
import logging
import uuid
from collections.abc import AsyncIterator, Coroutine
from functools import lru_cache
from typing import Any

from app.models.analysis import AnalysisProgressEvent

logger = logging.getLogger(__name__)


def analysis_job_key(identifier: str) -> str:
    """Progress-channel key for an analysis.

    Namespaced because an evaluation run id and an analysis id are drawn from
    different id spaces and could collide. A bare string key would then
    cross-wire two WebSocket channels.
    """
    return f"analysis:{identifier}"


def evaluation_job_key(run_id: str) -> str:
    """Progress-channel key for an evaluation run. See `analysis_job_key`."""
    return f"evaluation:{run_id}"


def _log_task_exception(job_id: str, task: "asyncio.Task[Any]") -> None:
    """Surface a fire-and-forget job's failure instead of losing it.

    Nothing else ever awaits a task started by `enqueue`, so without this
    callback an exception raised inside it would sit invisible until
    Python's own "Task exception was never retrieved" warning fires at
    garbage-collection time -- unpredictable, easy to miss, and stripped of
    any context about which job failed. Logged immediately instead, with
    the job id that `enqueue` returned to its caller.
    """
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("enqueued job %s failed: %s", job_id, exc, exc_info=exc)


class JobQueue:
    """In-process job queue with per-session progress fan-out.

    Single-process by design: this backend runs as one uvicorn worker.
    Both `_subscribers` and `_tasks` live only in that process's memory --
    they are NOT backed by anything durable. That means: a WebSocket
    subscriber only ever sees events published by an analysis running in
    the SAME process (fine today, since there's exactly one); the queue
    cannot be shared across multiple uvicorn workers if this ever scales
    beyond one; and a process restart silently drops every open
    subscription and every tracked job id, with no persistence or replay.
    Moving to multiple workers, or surviving a restart, would require an
    external broker (e.g. Redis pub/sub) in place of this class.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    def enqueue(self, job_key: str, coro: Coroutine[Any, Any, Any]) -> str:
        """Fire-and-forget `coro`, tracked by a generated job id.

        Not currently wired to any caller: `POST /api/analyze/{session_id}`
        (`app/routers/analyze.py`) still calls `run_analysis` directly and
        awaits it inline, matching the brief's own sample route -- so today
        a slow analysis blocks the HTTP request that triggered it. This
        method exists because the brief's public interface requires
        `JobQueue.enqueue(job_key) -> str`; it's kept, documented, and
        made safe (see `_log_task_exception`) rather than removed, for
        whoever wires up true background dispatch later. `job_key` is
        accepted (matching that interface) but not otherwise used here --
        `coro` is expected to already be the call that will itself publish
        progress for that job via `publish`.
        """
        job_id = str(uuid.uuid4())
        task = asyncio.create_task(coro)
        task.add_done_callback(lambda t: _log_task_exception(job_id, t))
        self._tasks[job_id] = task
        return job_id

    async def publish(self, job_key: str, event: AnalysisProgressEvent) -> None:
        for queue in list(self._subscribers.get(job_key, [])):
            await queue.put(event)

    async def subscribe(self, job_key: str) -> AsyncIterator[AnalysisProgressEvent]:
        """Stream progress events for `job_key` as they're published.

        No history/replay: a subscriber only ever receives events published
        AFTER it calls `subscribe` (see `app/routers/analyze.py`'s
        WebSocket handler). A client that connects after an analysis has
        already finished sees nothing and waits indefinitely -- there is no
        buffered backlog and no "already completed" signal on this channel.
        That's a deliberate scope boundary, not a bug: a caller that needs
        the outcome of a possibly-already-finished analysis should read it
        back via `GET /api/analysis/{id}` (or `/api/sessions/{id}`, once
        overlaid) instead of relying on this stream.
        """
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(job_key, []).append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers[job_key].remove(queue)


@lru_cache
def get_queue() -> JobQueue:
    return JobQueue()
