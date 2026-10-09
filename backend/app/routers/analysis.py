import uuid

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import assert_can_read, denied_honeypots, denies_everything, require_user
from app.models.analysis import SessionAnalysis
from app.routers.limits import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from app.services.analyzer import load_analysis, load_history
from app.services.session_builder import honeypots_for_sessions

router = APIRouter()


@router.get("/analysis", response_model=list[SessionAnalysis])
async def get_analysis_history(
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    claims: dict | None = Depends(require_user),
) -> list[SessionAnalysis]:
    if denies_everything(claims):
        return []
    return await load_history(limit=limit, deny_honeypots=denied_honeypots(claims))


@router.get("/analysis/{analysis_id}", response_model=SessionAnalysis)
async def get_analysis(
    analysis_id: str, claims: dict | None = Depends(require_user)
) -> SessionAnalysis:
    try:
        parsed = uuid.UUID(analysis_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="not an analysis id") from exc

    analysis = await load_analysis(parsed)
    if analysis is None:
        raise HTTPException(status_code=404, detail=f"unknown analysis {analysis_id}")

    # The honeypot is a property of the session, not of the analysis row, so
    # it has to be resolved before the scope can be applied. A session whose
    # events have aged out cannot be placed on a sensor, and an analysis that
    # cannot be placed is not shown to a scoped caller.
    owners = await honeypots_for_sessions([analysis.session_id])
    owner = owners.get(analysis.session_id)
    if owner is None:
        if denied_honeypots(claims) or denies_everything(claims):
            raise HTTPException(status_code=404, detail="not found")
    else:
        assert_can_read(claims, owner)
    return analysis
