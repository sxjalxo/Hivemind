import asyncio
import uuid
from collections.abc import AsyncIterator, Coroutine
from functools import lru_cache
from typing import Any

from app.models.analysis import AnalysisProgressEvent


class JobQueue:
    """In-process job queue with per-session progress fan-out.

    Single-process by design: this backend runs as one uvicorn worker.
    Moving to multiple workers would require Redis pub/sub here.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    def enqueue(self, session_id: str, coro: Coroutine[Any, Any, Any]) -> str:
        job_id = str(uuid.uuid4())
        self._tasks[job_id] = asyncio.create_task(coro)
        return job_id

    async def publish(self, session_id: str, event: AnalysisProgressEvent) -> None:
        for queue in list(self._subscribers.get(session_id, [])):
            await queue.put(event)

    async def subscribe(self, session_id: str) -> AsyncIterator[AnalysisProgressEvent]:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(session_id, []).append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers[session_id].remove(queue)


@lru_cache
def get_queue() -> JobQueue:
    return JobQueue()
