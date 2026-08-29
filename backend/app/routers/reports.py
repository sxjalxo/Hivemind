from fastapi import APIRouter, Body, HTTPException

from app.models.report import ThreatReport
from app.services.reports import create_report, list_reports

router = APIRouter()


@router.get("/reports", response_model=list[ThreatReport])
async def get_reports() -> list[ThreatReport]:
    return await list_reports()


@router.post("/reports", response_model=ThreatReport)
async def post_report(sessionId: str = Body(..., embed=True)) -> ThreatReport:  # noqa: N803
    try:
        return await create_report(sessionId)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
