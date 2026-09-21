from fastapi import APIRouter, Depends, HTTPException, WebSocket

from app.auth import Actor, assert_admin_for, require_admin
from app.db import locks
from app.models.analysis import SessionAnalysis
from app.services.analyzer import load_analysis, run_analysis
from app.services.session_builder import get_session
from app.workers.queue import analysis_job_key, stream_progress

router = APIRouter()

# Disjoint from every other advisory lock -- see `app.db.locks.lock_key`. An
# analysis of session "s-1" must not block anything else that happens to be
# named "s-1".
_LOCK_NAMESPACE = b"hivemind.analysis.session:"


# admin: one full LLM pipeline on the one GPU per call. The dependency is
# on the parameter rather than in `dependencies=[...]` so the handler also
# receives the claims -- it needs them for the per-honeypot check below,
# and declaring it twice would say the same thing in two places.
@router.post("/analyze/{session_id}", response_model=SessionAnalysis)
async def analyze(
    session_id: str,
    claims: dict | None = Depends(require_admin),
) -> SessionAnalysis:
    """Analyze one session and return the result.

    409 when an analysis of this session is already in progress. Two at once
    is not merely wasteful: both publish stages to the SAME progress channel
    (`analysis_job_key(session_id)`), so a client watching sees the two runs'
    stage indices interleaved and jumping backwards, with no way to tell
    which run any frame belongs to. They also both run the full LLM pipeline
    on one GPU, making each slower than one would have been, and both stamp
    `write_back_enrichment` onto the same Elasticsearch documents.

    The lock is the one the evaluation path already uses, with its own
    namespace -- see `app.db.locks`. `held` rather than `acquire`/`release`
    because this handler does the work inline, so the lock's lifetime is the
    request's; the evaluation route holds its lock across a background task
    and cannot use the context manager.

    This route stays synchronous, deliberately, unlike `POST /api/evaluations`
    which returns 202 and dispatches. The evaluation route has to: its
    progress channel is keyed by a run id that does not exist until the
    server allocates one, so the client cannot subscribe until the POST
    returns. This channel is keyed by the session id, which the CALLER
    already holds before it posts -- so a client subscribes first and then
    posts, and there is no window in which an event can be published to a
    channel nobody is listening on. The evaluation path structurally cannot
    close that window; this one has no window to close.
    """
    # Per-honeypot authorisation needs to know which honeypot this session
    # belongs to, and only the session tells us. `require_admin` has already
    # refused a caller who is admin nowhere, so this lookup cannot be used by
    # a pure viewer to probe which session ids exist.
    session = await get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"unknown session {session_id}")
    assert_admin_for(claims, session.honeypot_id)

    async with locks.held(_LOCK_NAMESPACE, session_id) as acquired:
        if not acquired:
            raise HTTPException(
                status_code=409,
                detail=f"an analysis is already running for session {session_id}",
            )
        try:
            analysis_id = await run_analysis(session_id, actor=Actor.from_claims(claims))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        analysis = await load_analysis(analysis_id)
        if analysis is None:
            raise HTTPException(status_code=500, detail="analysis vanished after write")
        return analysis


@router.websocket("/analyze/{session_id}/progress")
async def progress(websocket: WebSocket, session_id: str) -> None:
    # No history/replay -- see JobQueue.subscribe's docstring. A client that
    # connects here after the session's analysis has already finished gets
    # no frames and waits indefinitely; it should read the outcome back via
    # GET /api/analysis/{id} (or the overlaid /api/sessions/{id}) instead.
    #
    # `stream_progress` and not a subscribe loop here: a loop that only awaits
    # the next event cannot see its client disconnect, and this session's
    # analysis is exactly the kind that publishes its last frame and then
    # nothing ever again -- so the subscriber, the task and the socket would
    # never be released. See `app.workers.queue.stream_progress`.
    await stream_progress(websocket, analysis_job_key(session_id))
