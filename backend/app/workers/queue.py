import asyncio
import contextlib
import logging
import uuid
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from app.auth import authenticate_websocket
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

        Used by `POST /api/evaluations`, which must return a run id before
        the run publishes anything on that id's channel. `POST /api/analyze/
        {session_id}` does NOT use it and awaits `run_analysis` inline: its
        channel is keyed by the session id, which the caller already holds,
        so a client subscribes before it posts and no frame can be published
        to a channel nobody is listening on. Dispatching it would buy only
        the shorter request, at the cost of a second id for the client to
        track. See that route's docstring.

        `job_key` is accepted (the interface requires it) but not otherwise
        used here -- `coro` is expected to already be the call that will
        itself publish progress for that job via `publish`.
        """
        job_id = str(uuid.uuid4())
        task = asyncio.create_task(coro)
        # Registered before the callback, so the entry is already present when
        # a task that finishes immediately fires it.
        self._tasks[job_id] = task
        task.add_done_callback(lambda t: self._retire(job_id, t))
        return job_id

    def _retire(self, job_id: str, task: "asyncio.Task[Any]") -> None:
        """Drop a finished job, then report however it ended.

        The entry in `_tasks` exists for exactly one reason: the event loop
        keeps only a weak reference to a running task, so without a strong one
        here a long run can be garbage-collected mid-flight. That reason
        expires the moment the task is done, and nothing ever reads `_tasks`
        afterwards -- so leaving the entry grew the dict by one finished Task,
        its result and its coroutine frame for every run the process had ever
        dispatched. `_unsubscribe` already refuses to leak a key for the same
        reason; this is the same leak one attribute over.

        Only finished jobs are removed, which is what keeps the `drain` fixture
        in `test_evaluation_api` working: it awaits the runs still in flight at
        teardown, and a finished run is one it no longer needs to wait for.
        """
        self._tasks.pop(job_id, None)
        _log_task_exception(job_id, task)

    async def publish(self, job_key: str, event: AnalysisProgressEvent) -> None:
        for queue in list(self._subscribers.get(job_key, [])):
            await queue.put(event)

    def _unsubscribe(self, job_key: str, queue: "asyncio.Queue") -> None:
        """Drop one subscriber -- and the key itself once it holds none.

        Removing only the queue leaves `{job_key: []}` behind forever. That
        matters twice over. Ordinary use grows it: one empty list per run
        anyone ever opened a progress socket for, never reclaimed. And the
        key is caller-supplied -- there is no authentication anywhere in this
        app -- so a retained empty list per distinct key is a dict whose size
        and contents a caller chooses.
        """
        subscribers = self._subscribers.get(job_key)
        if subscribers is None:
            return
        with contextlib.suppress(ValueError):
            subscribers.remove(queue)
        if not subscribers:
            self._subscribers.pop(job_key, None)

    @asynccontextmanager
    async def subscription(self, job_key: str) -> AsyncIterator["asyncio.Queue"]:
        """Register a subscriber queue for `job_key`, and always deregister it.

        The one place a subscriber is added and removed. `subscribe` and
        `stream_progress` both go through it precisely so neither can grow a
        cleanup path of its own -- a handler that forgot to release its
        subscriber is the leak this exists to make unrepeatable.
        """
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(job_key, []).append(queue)
        try:
            yield queue
        finally:
            self._unsubscribe(job_key, queue)

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

        Note that a consumer of this generator only ever releases its
        subscriber when the generator is closed or exhausted. A WebSocket
        handler cannot guarantee that on its own, which is why one should
        call `stream_progress` rather than iterate this directly.
        """
        async with self.subscription(job_key) as queue:
            while True:
                yield await queue.get()


async def _wait_for_disconnect(websocket: WebSocket) -> None:
    """Return as soon as the client's half of `websocket` is gone.

    ASGI delivers a disconnect as a message on the RECEIVE channel and
    nowhere else. A handler that never reads that channel therefore cannot
    observe a client going away, no matter how long it waits.
    """
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
    except WebSocketDisconnect:
        return
    except RuntimeError:
        # Starlette raises this if the disconnect was already consumed
        # elsewhere; either way there is no client left to send to.
        return


async def stream_progress(
    websocket: WebSocket, job_key: str, *, queue: "JobQueue | None" = None
) -> None:
    """Accept `websocket` and forward `job_key`'s events until either side ends.

    Every progress route in this app goes through here, so that none of them
    can reintroduce the leak this closes.

    Why the receive side is raced against the next event, rather than simply
    iterating the subscription: a handler that only awaits the next event
    never learns its client has gone, because a disconnect arrives on the
    receive channel and nothing was reading it. A closed socket was then
    noticed only when some later event happened to be published on that exact
    key -- which, for a run that has already published its last stage, is
    never. The handler task, its queue, the socket and the `_subscribers`
    entry all outlived the client, and uvicorn, which waits for its ASGI
    tasks at shutdown, could not stop at all: after any client had opened a
    progress socket the process could only be force-killed. That is not an
    abuse case; it is what happens when someone watches a run and closes the
    tab.

    Nothing is read FROM the client: the receive task exists to detect the
    disconnect, and any frame a client sends is discarded. This channel is
    one-way by design.
    """
    jobs = queue if queue is not None else get_queue()

    # Authenticate BEFORE accepting. A browser cannot set an Authorization
    # header on a WebSocket handshake, so the token arrives as a subprotocol
    # (see `app.auth.websocket_token`) and the router-level HTTP dependency
    # cannot see it -- every progress channel would otherwise be readable by
    # anyone who could guess a run id, which is a uuid the POST just handed
    # out. Returns None and closes the socket itself when the token is
    # missing or bad; nothing further may be sent after that.
    allowed, subprotocol = await authenticate_websocket(websocket)
    if not allowed:
        return
    # Starlette sends no subprotocol when this is None, which is correct for a
    # client that offered none. Echoing one that was never offered fails the
    # handshake in the browser.
    await websocket.accept(subprotocol=subprotocol)
    async with jobs.subscription(job_key) as events:
        closed = asyncio.ensure_future(_wait_for_disconnect(websocket))
        try:
            while True:
                nxt = asyncio.ensure_future(events.get())
                try:
                    await asyncio.wait({nxt, closed}, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    # Never leave the pending get() behind: it holds a
                    # reference to the very queue we are about to release.
                    if not nxt.done():
                        nxt.cancel()
                if closed.done():
                    return
                await websocket.send_json(nxt.result().model_dump(by_alias=True))
        except WebSocketDisconnect:
            return
        finally:
            closed.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await closed


@lru_cache
def get_queue() -> JobQueue:
    return JobQueue()
