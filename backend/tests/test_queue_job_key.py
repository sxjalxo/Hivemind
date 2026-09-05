import pytest

from app.models.analysis import AnalysisProgressEvent, LiveAnalysisMetrics
from app.workers.queue import JobQueue, analysis_job_key, evaluation_job_key


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
