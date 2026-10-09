import asyncio
import contextlib

import pytest

from app.models.analysis import AnalysisProgressEvent, LiveAnalysisMetrics
from app.workers.queue import JobQueue, analysis_job_key, evaluation_job_key, stream_progress
from tests.conftest import FakeWebSocket


def test_namespaces_keep_identical_ids_apart() -> None:
    shared = "3fd2ac9c-c0b7-4adc-a7ea-44757f849cae"
    assert analysis_job_key(shared) != evaluation_job_key(shared)
    assert analysis_job_key(shared) == f"analysis:{shared}"
    assert evaluation_job_key(shared) == f"evaluation:{shared}"


@pytest.mark.asyncio
async def test_a_subscriber_only_sees_its_own_namespace() -> None:
    # An evaluation run whose id happens to equal an analysis id must not
    # receive that analysis's progress frames.
    import asyncio

    shared = "collision-id"
    queue = JobQueue()
    received: list[str] = []

    async def collect() -> None:
        async for event in queue.subscribe(evaluation_job_key(shared)):
            received.append(event.stage)

    task = asyncio.create_task(collect())
    await asyncio.sleep(0.01)

    await queue.publish(
        analysis_job_key(shared),
        AnalysisProgressEvent(
            stage_index=0, stage="parsing_logs", metrics=LiveAnalysisMetrics(progress_pct=14)
        ),
    )
    await queue.publish(
        evaluation_job_key(shared),
        AnalysisProgressEvent(
            stage_index=1, stage="identifying_patterns", metrics=LiveAnalysisMetrics(progress_pct=28)
        ),
    )

    await asyncio.sleep(0.1)
    task.cancel()

    assert len(received) == 1
    assert received[0] == "identifying_patterns"


# --- subscriber release -------------------------------------------------
#
# A progress handler that never releases its subscriber is not a slow leak in
# a corner: it is what happens when a user watches a run and closes the tab.
# The handler task, its queue, the socket and the `_subscribers` entry all
# outlive the client, and uvicorn -- which waits for its ASGI tasks -- then
# cannot shut down at all, so the process can only be force-killed.


@pytest.mark.asyncio
async def test_a_subscription_releases_its_queue_and_its_key() -> None:
    """The key goes too, not just the queue.

    Removing only the queue leaves `{key: []}` behind forever. The key is
    caller-supplied and there is no authentication anywhere in this app, so a
    retained empty list per distinct key is a dict a caller sizes.
    """
    queue = JobQueue()
    key = evaluation_job_key("11111111-2222-3333-4444-555555555555")

    async with queue.subscription(key) as subscriber:
        assert queue._subscribers[key] == [subscriber]

    assert key not in queue._subscribers
    assert queue._subscribers == {}


@pytest.mark.asyncio
async def test_many_distinct_keys_retain_nothing_once_their_subscribers_go() -> None:
    queue = JobQueue()
    for index in range(1000):
        async with queue.subscription(evaluation_job_key(f"junk-{index}")):
            pass
    assert queue._subscribers == {}


@pytest.mark.asyncio
async def test_a_key_survives_while_another_subscriber_still_holds_it() -> None:
    """Popping the key must not evict a second viewer of the same run."""
    queue = JobQueue()
    key = evaluation_job_key("shared-run")

    async with queue.subscription(key) as first:
        async with queue.subscription(key):
            assert len(queue._subscribers[key]) == 2
        assert queue._subscribers[key] == [first]

    assert key not in queue._subscribers


def _event(stage_index: int, stage: str) -> AnalysisProgressEvent:
    return AnalysisProgressEvent(
        stage_index=stage_index,
        stage=stage,
        metrics=LiveAnalysisMetrics(progress_pct=10 * stage_index),
    )


@pytest.mark.asyncio
async def test_a_disconnected_client_ends_the_handler_and_frees_its_subscriber() -> None:
    """The property a hung uvicorn shutdown is made of.

    A full uvicorn lifecycle test would need a server thread, a real socket
    and a ten-second join for each of a control and a test case -- too heavy
    for this suite to carry on every run. So the property that MADE that
    server hang is asserted here directly on the handler: the task completes,
    and the subscription's release runs. `asyncio.wait_for` is the assertion;
    before the fix the handler simply never returned, because nothing was
    reading the receive channel a disconnect arrives on and no further event
    was ever going to be published for a finished run. The end-to-end
    control/test pair was run separately against a real uvicorn server.
    """
    queue = JobQueue()
    key = evaluation_job_key("9d2b0a10-0000-4000-8000-000000000001")
    socket = FakeWebSocket()

    handler = asyncio.create_task(stream_progress(socket, key, queue=queue))
    await asyncio.sleep(0.05)  # let it accept and register
    assert socket.accepted
    assert len(queue._subscribers[key]) == 1

    socket.disconnect()
    await asyncio.wait_for(handler, timeout=5)

    assert handler.done() and not handler.cancelled()
    assert queue._subscribers == {}


@pytest.mark.asyncio
async def test_the_handler_leaves_nothing_behind_when_no_event_is_ever_published() -> None:
    """The ordinary case, not the abuse case.

    A user opens the progress socket for a run that has already published its
    last stage, then closes the tab. Nothing will ever be published on that
    key again, so a handler that notices a disconnect only when the next
    event arrives never notices at all.
    """
    queue = JobQueue()
    key = evaluation_job_key("9d2b0a10-0000-4000-8000-000000000002")
    socket = FakeWebSocket()

    handler = asyncio.create_task(stream_progress(socket, key, queue=queue))
    await asyncio.sleep(0.05)
    socket.disconnect()
    await asyncio.wait_for(handler, timeout=5)

    assert socket.sent == []
    assert queue._subscribers == {}


@pytest.mark.asyncio
async def test_watching_for_a_disconnect_does_not_stop_events_flowing() -> None:
    """Closing the leak must not cost the channel its only job."""
    queue = JobQueue()
    key = evaluation_job_key("9d2b0a10-0000-4000-8000-000000000003")
    socket = FakeWebSocket()

    handler = asyncio.create_task(stream_progress(socket, key, queue=queue))
    await asyncio.sleep(0.05)
    try:
        await queue.publish(key, _event(0, "parsing_logs"))
        await queue.publish(key, _event(1, "identifying_patterns"))
        await asyncio.sleep(0.05)
        assert [frame["stage"] for frame in socket.sent] == [
            "parsing_logs",
            "identifying_patterns",
        ]
    finally:
        socket.disconnect()
        await asyncio.wait_for(handler, timeout=5)

    assert queue._subscribers == {}


# --- dispatched-job release ---------------------------------------------
#
# `_subscribers` was taught not to retain a key; `_tasks` had the same leak one
# attribute over. The entry exists only to stop the event loop -- which holds a
# weak reference to a running task -- collecting a long run mid-flight, and
# nothing ever reads it afterwards.


@pytest.mark.asyncio
async def test_a_finished_job_is_not_retained() -> None:
    queue = JobQueue()

    async def work() -> None:
        await asyncio.sleep(0)

    job_id = queue.enqueue(evaluation_job_key("retire-ok"), work())
    task = queue._tasks[job_id]  # held while in flight, which is the point

    await asyncio.wait_for(task, timeout=5)
    await asyncio.sleep(0)  # let the done-callback run
    assert queue._tasks == {}


@pytest.mark.asyncio
async def test_a_failed_job_is_retired_too() -> None:
    """A run that raised is exactly the one a leak would pin in memory."""
    queue = JobQueue()

    async def boom() -> None:
        raise RuntimeError("run failed")

    job_id = queue.enqueue(evaluation_job_key("retire-boom"), boom())
    task = queue._tasks[job_id]

    with contextlib.suppress(RuntimeError):
        await asyncio.wait_for(task, timeout=5)
    await asyncio.sleep(0)
    assert queue._tasks == {}


@pytest.mark.asyncio
async def test_many_dispatched_jobs_retain_nothing() -> None:
    queue = JobQueue()

    async def work() -> None:
        await asyncio.sleep(0)

    tasks = []
    for index in range(200):
        job_id = queue.enqueue(evaluation_job_key(f"bulk-{index}"), work())
        tasks.append(queue._tasks[job_id])

    await asyncio.gather(*tasks)
    await asyncio.sleep(0)
    assert queue._tasks == {}
