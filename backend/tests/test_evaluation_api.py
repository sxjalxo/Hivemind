"""The HTTP/WebSocket surface for evaluation runs.

Two disciplines are asserted here rather than merely documented:

**Containment.** There must be no code path from an HTTP request to an
arbitrary host or command. The request body carries a honeypot id and nothing
else -- no host, no port, no address -- and that id must resolve through the
honeypot registry before anything runs. `test_the_request_body_has_no_field_
for_a_host_or_port` reads the published OpenAPI schema, so a field added later
fails a test rather than quietly widening the attack surface.

**One run at a time per honeypot.** Two overlapping runs reset the same
container underneath each other and interleave their traffic into each
other's chain read-back windows, which is exactly the evidence
mis-attribution Task 14 fixed. `runs.is_running` is a bare SELECT and cannot
enforce it, so the router takes a Postgres advisory lock; the concurrency
test below is what proves the lock and not the SELECT is doing the work.

Every test that writes a row removes it, in teardown that runs whether the
test passed or failed.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone

import httpx
import pytest_asyncio

from app.db.models import EvaluationCategoryScore, EvaluationRun
from app.db.session import get_session_factory
from app.main import app
from app.models.evaluation import EvaluationProgressEvent
from app.models.honeypot import Honeypot
from app.routers import evaluation
from app.auth import Actor
from app.services.evaluation import runs
from app.services.evaluation.reset import ResetError
from app.workers.queue import evaluation_job_key, get_queue
from tests.conftest import asgi_websocket

HONEYPOT_ID = "cowrie-01"


async def _client() -> httpx.AsyncClient:
    # Never a bare TestClient: it opens a fresh anyio portal per request and
    # poisons the cached aiohttp session for every later async test.
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _honeypot(honeypot_id: str) -> Honeypot:
    return Honeypot(
        id=honeypot_id,
        name=honeypot_id,
        type="SSH",
        os="Debian 11 (emulated)",
        interaction_level="medium",
        ip="172.20.0.3",
        status="online",
        active_sessions=0,
        events=0,
        last_activity="2026-09-08T00:00:00Z",
        risk="low",
    )


def _register(monkeypatch, honeypot_id: str = HONEYPOT_ID) -> None:
    """Make `honeypot_id` a registered honeypot without going near Elasticsearch."""

    async def _list_honeypots() -> list[Honeypot]:
        return [_honeypot(honeypot_id)]

    monkeypatch.setattr(evaluation, "list_honeypots", _list_honeypots)


@pytest_asyncio.fixture(loop_scope="session")
async def drain():
    """Await every background run this test dispatched before the next one starts.

    The POST returns 202 and leaves an `asyncio.Task` behind holding the
    honeypot's advisory lock on a pooled connection. A test that walked away
    from that task would leave the lock held for the rest of the session and
    every later POST would 409. Teardown runs whether the test passed or not.
    """
    queue = get_queue()
    before = set(queue._tasks)
    yield
    for job_id in [job for job in queue._tasks if job not in before]:
        task = queue._tasks.pop(job_id)
        try:
            await asyncio.wait_for(task, timeout=30)
        except Exception as exc:  # noqa: BLE001 - the assertion is the report, not this
            print(f"background run {job_id} ended with {type(exc).__name__}: {exc}")


@pytest_asyncio.fixture(loop_scope="session")
async def gate():
    """A stalled run that is always released, even by a failing assertion.

    Request this AFTER `drain` so its teardown runs FIRST: releasing the gate
    here is what lets `drain` collect the background task instead of waiting
    out its timeout. A test that set the gate on its last line would hang
    teardown for 30s per dispatched run the moment an assertion failed.
    """
    event = asyncio.Event()
    yield event
    event.set()


@pytest_asyncio.fixture(loop_scope="session")
async def created():
    """Rows written by hand, removed whether the test passed, failed or raised."""
    run_ids: list[uuid.UUID] = []

    async def _insert(honeypot_id: str = HONEYPOT_ID, status: str = "completed") -> uuid.UUID:
        run_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        async with get_session_factory()() as db:
            db.add(
                EvaluationRun(
                    id=run_id,
                    honeypot_id=honeypot_id,
                    status=status,
                    started_at=now,
                    finished_at=now,
                    agent_model="deterministic-probes@test",
                    evaluator_model=None,
                    evaluator_status="unavailable",
                    honeypot_fingerprint="sha256:TEST",
                    evaluation_config_fingerprint="sha256:TESTCONFIG",
                )
            )
            # No ORM relationship joins these two tables, so the unit of work
            # cannot know the score depends on the run. Flush the parent
            # first or the FK fires.
            await db.flush()
            db.add(
                EvaluationCategoryScore(
                    run_id=run_id,
                    characteristic="filesystem_realism",
                    deterministic_score=0.5,
                    evaluator_rating=None,
                )
            )
            await db.commit()
        run_ids.append(run_id)
        return run_id

    yield _insert
    for run_id in run_ids:
        await runs.delete_run(run_id)


# --- containment --------------------------------------------------------


async def test_starting_a_run_accepts_only_a_registered_honeypot_id() -> None:
    """The target is resolved from the registry, never from the request.

    The id below is shaped like a host:port precisely because that is what an
    attacker would try to smuggle through this field. It is not a registered
    honeypot, so it is refused before anything runs.
    """
    async with await _client() as client:
        response = await client.post("/api/evaluations", json={"honeypotId": "10.0.0.5:22"})
    assert response.status_code == 404
    # Names the id it refused, so this cannot pass merely because the route
    # is absent -- a missing route 404s too.
    assert "10.0.0.5:22" in response.json()["detail"]


async def test_the_request_body_has_no_field_for_a_host_or_port() -> None:
    schema = app.openapi()["components"]["schemas"]["StartEvaluationRequest"]
    assert set(schema["properties"]) == {"honeypotId"}


# --- dispatch -----------------------------------------------------------


async def test_a_successful_post_returns_202_without_waiting_for_the_run(
    monkeypatch, drain, gate
) -> None:
    """202 and a run id, while the run is still on its first stage.

    Awaiting `start_run` inline would mean waiting for a reset, an nmap scan,
    a 120s agent budget, a 30s chain-ingest poll and one LLM call per
    characteristic before the client learns the run's id -- by which time the
    progress channel it would subscribe to has nothing left to say.
    """
    _register(monkeypatch)
    finished = asyncio.Event()

    async def _slow(honeypot_id: str, run_id: uuid.UUID | None = None, actor: Actor | None = None) -> uuid.UUID:
        await gate.wait()
        finished.set()
        return run_id

    monkeypatch.setattr(runs, "start_run", _slow)

    async with await _client() as client:
        response = await client.post("/api/evaluations", json={"honeypotId": HONEYPOT_ID})

    assert response.status_code == 202
    assert uuid.UUID(response.json()["runId"])
    assert not finished.is_set()


async def test_the_progress_channel_uses_an_id_the_client_already_has(
    monkeypatch, drain, gate
) -> None:
    """POST -> id -> subscribe -> stages.

    `JobQueue.subscribe` has no replay, so the id must reach the client
    BEFORE the run publishes anything. This drives the real WebSocket handler
    against the real channel key and stalls the run until the subscription
    exists.
    """
    _register(monkeypatch)

    async def _emit_once(honeypot_id: str, run_id: uuid.UUID | None = None, actor: Actor | None = None) -> uuid.UUID:
        await gate.wait()
        await runs._emit(run_id, 1)
        return run_id

    monkeypatch.setattr(runs, "start_run", _emit_once)

    async with await _client() as client:
        response = await client.post("/api/evaluations", json={"honeypotId": HONEYPOT_ID})
    run_id = response.json()["runId"]

    received: asyncio.Queue = asyncio.Queue()

    class _Socket:
        def __init__(self) -> None:
            self.accepted = False
            # The handshake headers, where a Clerk token would arrive as a
            # subprotocol. Empty is an unauthenticated client, which is what
            # this test wants: `CLERK_ISSUER` is unset here, so the handler
            # accepts it exactly as a real one would.
            self.headers: dict[str, str] = {}
            self._incoming: asyncio.Queue = asyncio.Queue()

        async def accept(self, subprotocol: str | None = None) -> None:
            self.accepted = True

        async def close(self, code: int = 1000) -> None:
            self.closed_with = code

        async def receive(self) -> dict:
            # A connected client that sends nothing. The handler now watches
            # this channel for the disconnect ASGI delivers on it, so a fake
            # without `receive` is no longer a WebSocket -- see
            # `app.workers.queue.stream_progress`.
            return await self._incoming.get()

        async def send_json(self, payload: dict) -> None:
            await received.put(payload)

        def disconnect(self) -> None:
            self._incoming.put_nowait({"type": "websocket.disconnect", "code": 1000})

    socket = _Socket()
    listener = asyncio.create_task(evaluation.progress(socket, uuid.UUID(run_id)))
    for _ in range(20):  # let the handler accept and register its subscription
        await asyncio.sleep(0)
    assert socket.accepted

    gate.set()
    event = await asyncio.wait_for(received.get(), timeout=5)
    socket.disconnect()
    await asyncio.wait_for(listener, timeout=5)

    assert event["stage"] == "scanning_services"
    assert event["stageIndex"] == 1


async def test_a_start_failure_before_any_row_exists_is_visible(monkeypatch, caplog, drain) -> None:
    """A reset or fingerprint failure aborts before the run row exists.

    In a background task that exception reaches nobody: `GET
    /evaluations/{id}` would 404 with no explanation and the WebSocket would
    hang forever. Our own failure is reported, never hidden -- so it is
    published as a terminal event on the run's own channel and logged.
    """
    _register(monkeypatch)
    published: list[tuple[str, object]] = []
    queue = get_queue()
    real_publish = queue.publish

    async def _record(job_key: str, event) -> None:
        published.append((job_key, event))
        await real_publish(job_key, event)

    monkeypatch.setattr(queue, "publish", _record)

    async def _boom(honeypot_id: str, run_id: uuid.UUID | None = None, actor: Actor | None = None) -> uuid.UUID:
        raise ResetError("cowrie container is not running")

    monkeypatch.setattr(runs, "start_run", _boom)

    with caplog.at_level("ERROR"):
        async with await _client() as client:
            response = await client.post("/api/evaluations", json={"honeypotId": HONEYPOT_ID})
        run_id = response.json()["runId"]
        for _ in range(50):  # let the dispatched task run to completion
            await asyncio.sleep(0)

    keyed = [event for key, event in published if key == evaluation_job_key(run_id)]
    assert keyed, "a run that never started published nothing on its own channel"
    assert keyed[-1].stage == "failed"
    assert "cowrie container is not running" in (keyed[-1].error or "")
    assert any("cowrie container is not running" in record.getMessage() or record.exc_info
               for record in caplog.records)


# --- one run at a time --------------------------------------------------


async def test_a_second_run_for_the_same_honeypot_is_refused(monkeypatch, drain, gate) -> None:
    _register(monkeypatch)

    async def _slow(honeypot_id: str, run_id: uuid.UUID | None = None, actor: Actor | None = None) -> uuid.UUID:
        await gate.wait()
        return run_id

    monkeypatch.setattr(runs, "start_run", _slow)

    async with await _client() as client:
        first = await client.post("/api/evaluations", json={"honeypotId": HONEYPOT_ID})
        second = await client.post("/api/evaluations", json={"honeypotId": HONEYPOT_ID})

    assert first.status_code == 202
    assert second.status_code == 409


async def test_the_one_run_guard_holds_under_two_concurrent_requests(
    monkeypatch, drain, gate
) -> None:
    """The guard cannot be a bare SELECT.

    `runs.is_running` reads no row here -- `start_run` is stubbed, so nothing
    is ever inserted -- which means only the advisory lock can produce the
    409. Two concurrent requests, one admission.
    """
    _register(monkeypatch)

    async def _slow(honeypot_id: str, run_id: uuid.UUID | None = None, actor: Actor | None = None) -> uuid.UUID:
        await gate.wait()
        return run_id

    monkeypatch.setattr(runs, "start_run", _slow)

    async with await _client() as client:
        body = {"honeypotId": HONEYPOT_ID}
        responses = await asyncio.gather(
            client.post("/api/evaluations", json=body),
            client.post("/api/evaluations", json=body),
        )

    assert sorted(response.status_code for response in responses) == [202, 409]


# --- read side ----------------------------------------------------------


async def test_compare_rejects_an_unknown_run_id(created) -> None:
    known = await created()
    async with await _client() as client:
        response = await client.get(
            "/api/evaluations/compare", params={"base": str(known), "head": str(uuid.uuid4())}
        )
    assert response.status_code == 404


async def test_compare_is_routed_before_the_run_id_path(created) -> None:
    """`/evaluations/compare` must not be matched as a run id."""
    base = await created()
    head = await created()
    async with await _client() as client:
        response = await client.get(
            "/api/evaluations/compare", params={"base": str(base), "head": str(head)}
        )
    assert response.status_code == 200
    assert response.json()["classification"] == "same_configuration"


async def test_an_unknown_run_id_is_404() -> None:
    missing = uuid.uuid4()
    async with await _client() as client:
        response = await client.get(f"/api/evaluations/{missing}")
    assert response.status_code == 404
    # Names the id, so a missing route cannot make this pass.
    assert str(missing) in response.json()["detail"]


async def test_the_list_endpoint_is_bounded_and_not_fully_hydrated(created) -> None:
    """A history page must not transfer the entire evaluation database.

    `EvaluationRunOut` carries every probe result, finding, evidence row and
    chain step, at ~7 queries per run. The list endpoint returns the summary
    that renders a history row and a trend, and nothing else.
    """
    await created()
    await created()

    async with await _client() as client:
        bounded = await client.get("/api/evaluations", params={"limit": 1})
        over = await client.get("/api/evaluations", params={"limit": 1000})

    assert bounded.status_code == 200
    assert len(bounded.json()) == 1
    assert over.status_code == 422  # the bound is enforced, not merely suggested

    row = bounded.json()[0]
    assert set(row) == {
        "id",
        "honeypotId",
        "status",
        "startedAt",
        "finishedAt",
        "agentModel",
        "evaluatorModel",
        "evaluatorStatus",
        "honeypotFingerprint",
        "evaluationConfigFingerprint",
        "categoryScores",
        # Who started the run. Cheap scalars, so they belong on the summary
        # rather than only on the fully hydrated detail: a history row that
        # cannot say who ran something is most of what an audit trail is for.
        "startedBy",
        "startedByLabel",
    }
    assert row["categoryScores"][0]["deterministicScore"] == 0.5
    # None means "not established" and is carried, never coerced to 0.
    assert row["categoryScores"][0]["evaluatorRating"] is None


async def test_the_detail_endpoint_is_still_fully_hydrated(created) -> None:
    run_id = await created()
    async with await _client() as client:
        response = await client.get(f"/api/evaluations/{run_id}")
    assert response.status_code == 200
    assert set(response.json()) >= {"probeResults", "findings", "chainSteps", "modules"}


# --- startup ------------------------------------------------------------


async def test_stale_runs_are_reconciled_at_startup(monkeypatch) -> None:
    """A run orphaned by a killed process must not lock its honeypot out.

    `start_run` reconciles only the honeypot it was called for, so without a
    startup sweep an orphan is cleared only by the next run of that same
    honeypot -- which is the run the orphan is blocking.

    Startup must use the AGE-BLIND sweep. The age-based one leaves a row
    killed two minutes ago alone for the full 45-minute cutoff, and every POST
    for that honeypot in the meantime is refused with "an evaluation is
    already running" -- which is false. Nothing this process started can be
    live here, so age is not a question worth asking.
    """
    from app import main
    from app.seed import seeder

    calls: list[str] = []

    async def _age_based(honeypot_id: str | None = None) -> list:
        calls.append(f"age-based:{honeypot_id}")
        return []

    async def _at_startup() -> list:
        calls.append("startup")
        return []

    async def _noop(*args, **kwargs) -> None:
        return None

    async def _seeded_count() -> int:
        return 1

    class _Closable:
        async def close(self) -> None:
            return None

        async def dispose(self) -> None:
            return None

    monkeypatch.setattr(runs, "reconcile_stale_runs", _age_based)
    monkeypatch.setattr(runs, "reconcile_orphaned_runs_at_startup", _at_startup)
    monkeypatch.setattr(main, "bootstrap_es", _noop)
    monkeypatch.setattr(main, "get_es", lambda: _Closable())
    monkeypatch.setattr(main, "get_engine", lambda: _Closable())
    monkeypatch.setattr(seeder, "seeded_count", _seeded_count)

    async with main.lifespan(app):
        pass

    assert calls == ["startup"], (
        "startup must sweep every honeypot and every age, not one honeypot "
        "and only rows older than the cutoff"
    )


# --- the progress channel -----------------------------------------------
#
# The channel's failure modes are both silent. A handler that cannot see its
# client disconnect holds a task, a queue, a socket and a `_subscribers` entry
# for the life of the process -- and uvicorn, which waits for its ASGI tasks,
# then cannot shut down at all, so the backend can only be force-killed once
# anyone has watched a run. A run id spelled differently on the WebSocket than
# on the GET connects, is accepted, and receives nothing forever.


async def test_a_client_that_closes_cleanly_leaves_no_subscriber_behind() -> None:
    """One per viewed run, otherwise, and never reclaimed.

    Not an abuse case: the last stage publishes, the user closes the tab, and
    nothing is ever published on that key again -- so a handler that only
    wakes on the next event never wakes.
    """
    queue = get_queue()
    run_id = uuid.uuid4()
    key = evaluation_job_key(str(run_id))
    assert key not in queue._subscribers

    async with asgi_websocket(app, f"/api/evaluations/{run_id}/progress") as session:
        assert session.accepted
        assert len(queue._subscribers[key]) == 1

        session.disconnect()
        # The handler task COMPLETES. Before the fix it never returned, which
        # is precisely what stopped uvicorn from shutting down.
        await asyncio.wait_for(session.task, timeout=5)

    assert key not in queue._subscribers, "the key itself is retained, not just the queue"


async def test_a_run_id_spelled_differently_still_reaches_the_same_channel() -> None:
    """`GET /api/evaluations/{run_id}` normalises these; the socket must too.

    Publishers key on `str(run_id)`, which is canonical lowercase. With a raw
    `str` path parameter, a client that passed the uppercase spelling to both
    endpoints got a valid GET and a WebSocket that connected, was accepted,
    and then sat silent forever with no error and no close frame.
    """
    queue = get_queue()
    run_id = uuid.uuid4()
    canonical = evaluation_job_key(str(run_id))

    for spelling in (str(run_id).upper(), "{" + str(run_id) + "}", str(run_id).replace("-", "")):
        async with asgi_websocket(app, f"/api/evaluations/{spelling}/progress") as session:
            assert session.accepted, spelling
            assert canonical in queue._subscribers, spelling

            # Proof it is the same channel and not merely a plausible key:
            # a publish under the canonical key arrives on this socket.
            await queue.publish(
                canonical,
                EvaluationProgressEvent(stage_index=1, stage="scanning_services"),
            )
            frame = await session.receive()
            assert json.loads(frame["text"])["stage"] == "scanning_services", spelling

            session.disconnect()
            await asyncio.wait_for(session.task, timeout=5)

        assert canonical not in queue._subscribers, spelling


async def test_an_id_that_is_not_a_run_id_at_all_is_refused_a_channel() -> None:
    """No subscriber is allocated for something that cannot name a run."""
    queue = get_queue()
    before = set(queue._subscribers)

    async with asgi_websocket(app, "/api/evaluations/not-a-run-id/progress") as session:
        assert not session.accepted
        assert session.opening["type"] == "websocket.close"

    assert set(queue._subscribers) == before


async def test_category_scores_carry_their_own_evaluator_status() -> None:
    """The run header cannot say which characteristic was blank; the row can."""
    from sqlalchemy import delete

    run_id = uuid.uuid4()
    async with get_session_factory()() as db:
        db.add(
            EvaluationRun(
                id=run_id,
                honeypot_id="cowrie-01",
                status="completed",
                started_at=datetime.now(timezone.utc),
                agent_model="none",
                evaluator_status="completed",
                honeypot_fingerprint="sha256:test",
                evaluation_config_fingerprint="sha256:test",
                started_by="unauthenticated",
            )
        )
        await db.flush()
        db.add(
            EvaluationCategoryScore(
                run_id=run_id,
                characteristic="os_identity",
                deterministic_score=0.5,
                evaluator_rating=None,
                evaluator_status="evaluator_failed",
                evaluator_detail="verdict rejected: no cited evidence resolved",
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/evaluations/{run_id}")

    assert response.status_code == 200
    scores = response.json()["categoryScores"]
    row = next(s for s in scores if s["characteristic"] == "os_identity")
    # The run says `completed`; this characteristic did not. That difference
    # is the whole point of the column.
    assert response.json()["evaluatorStatus"] == "completed"
    assert row["evaluatorStatus"] == "evaluator_failed"
    assert row["evaluatorDetail"] == "verdict rejected: no cited evidence resolved"

    async with get_session_factory()() as db:
        await db.execute(
            delete(EvaluationCategoryScore).where(EvaluationCategoryScore.run_id == run_id)
        )
        await db.execute(delete(EvaluationRun).where(EvaluationRun.id == run_id))
        await db.commit()
