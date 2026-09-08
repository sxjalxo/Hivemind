from fastapi import APIRouter, HTTPException, WebSocket

from app.models.analysis import SessionAnalysis
from app.services.analyzer import load_analysis, run_analysis
from app.workers.queue import analysis_job_key, stream_progress

router = APIRouter()


@router.post("/analyze/{session_id}", response_model=SessionAnalysis)
async def analyze(session_id: str) -> SessionAnalysis:
    try:
        analysis_id = await run_analysis(session_id)
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
