"""Progress fan-out across processes over Redis.

Two JobQueue instances stand in for two uvicorn workers: same Redis, different
`origin`. Runs against the stack's Redis (`docker compose up -d redis`).
"""

import asyncio
import contextlib

import pytest
import redis.asyncio as aioredis

from app.models.analysis import AnalysisProgressEvent
from app.workers.queue import _REDIS_CHANNEL, JobQueue

REDIS_URL = "redis://127.0.0.1:6379/15"


async def _redis_up() -> bool:
    client = aioredis.from_url(REDIS_URL)
    try:
        return bool(await client.ping())
    except Exception:  # noqa: BLE001
        return False
    finally:
        await client.aclose()


async def _listeners_ready(expected: int) -> None:
    """Wait until `expected` listeners are subscribed; publish before that is lost."""
    client = aioredis.from_url(REDIS_URL)
    try:
        for _ in range(60):
            [(_, count)] = await client.pubsub_numsub(_REDIS_CHANNEL)
            if count >= expected:
                return
            await asyncio.sleep(0.05)
        raise AssertionError("Redis listener never subscribed")
    finally:
        await client.aclose()


async def _drain(queue: asyncio.Queue, wait: float = 0.5) -> list:
    items = []
    try:
        while True:
            items.append(await asyncio.wait_for(queue.get(), timeout=wait))
    except TimeoutError:
        return items


def _event(index: int) -> AnalysisProgressEvent:
    return AnalysisProgressEvent(stage_index=index, stage=f"stage-{index}")


# A context manager, not an async fixture: the listener task belongs to the loop
# that started it, and a fixture's teardown runs on a different one.
@contextlib.asynccontextmanager
async def _workers():
    if not await _redis_up():
        pytest.skip("Redis is not running: docker compose up -d redis")
    a, b = JobQueue(REDIS_URL), JobQueue(REDIS_URL)
    try:
        yield a, b
    finally:
        await a.close()
        await b.close()


async def test_a_socket_on_one_worker_sees_a_run_on_another() -> None:
    async with _workers() as (subscriber_side, run_side):
        async with subscriber_side.subscription("analysis:s1") as queue:
            await _listeners_ready(1)
            await run_side.publish("analysis:s1", _event(3))
            [received] = await _drain(queue)

        # Relayed events arrive as the serialised dict the socket sends as-is.
        assert received == {"stageIndex": 3, "stage": "stage-3", "metrics": None}


async def test_the_publishing_worker_delivers_once_not_twice() -> None:
    async with _workers() as (a, b):
        async with (
            a.subscription("analysis:s2") as queue_a,
            b.subscription("analysis:s2") as queue_b,
        ):
            await _listeners_ready(2)
            await a.publish("analysis:s2", _event(1))
            on_a, on_b = await _drain(queue_a), await _drain(queue_b)

        assert len(on_a) == 1 and isinstance(on_a[0], AnalysisProgressEvent)  # local path
        assert len(on_b) == 1 and on_b[0]["stageIndex"] == 1  # relayed once


async def test_a_different_key_is_not_delivered() -> None:
    async with _workers() as (a, b), a.subscription("analysis:mine") as queue:
        await _listeners_ready(1)
        await b.publish("analysis:theirs", _event(1))
        assert await _drain(queue) == []


async def test_with_redis_down_the_local_path_still_works() -> None:
    queue = JobQueue("redis://127.0.0.1:1/0")  # nothing listens on port 1
    try:
        async with queue.subscription("analysis:s3") as local:
            await queue.publish("analysis:s3", _event(2))  # must not raise
            [received] = await _drain(local)
        assert received.stage_index == 2
    finally:
        await queue.close()
