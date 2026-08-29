import uuid

from fastapi import APIRouter, HTTPException

from app.models.analysis import SessionAnalysis
from app.services.analyzer import load_analysis, load_history

router = APIRouter()


@router.get("/analysis", response_model=list[SessionAnalysis])
async def get_analysis_history() -> list[SessionAnalysis]:
    return await load_history()


@router.get("/analysis/{analysis_id}", response_model=SessionAnalysis)
async def get_analysis(analysis_id: str) -> SessionAnalysis:
    try:
        parsed = uuid.UUID(analysis_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="not an analysis id") from exc

    analysis = await load_analysis(parsed)
    if analysis is None:
        raise HTTPException(status_code=404, detail=f"unknown analysis {analysis_id}")
    return analysis
