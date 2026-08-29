from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from app.models.analysis import SessionAnalysis
from app.services.analyzer import load_analysis, run_analysis
from app.workers.queue import get_queue

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
    await websocket.accept()
    try:
        async for event in get_queue().subscribe(session_id):
            await websocket.send_json(event.model_dump(by_alias=True))
    except WebSocketDisconnect:
        return
