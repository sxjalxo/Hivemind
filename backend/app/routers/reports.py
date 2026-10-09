from fastapi import APIRouter, Body, Depends, HTTPException, Query

from app.auth import Actor, assert_admin_for, require_admin

from app.models.report import ThreatReport
from app.routers.limits import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from app.services.reports import create_report, list_reports
from app.services.session_builder import get_session

router = APIRouter()


@router.get("/reports", response_model=list[ThreatReport])
async def get_reports(
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
) -> list[ThreatReport]:
    return await list_reports(limit=limit)


# admin: `create_report` runs an analysis when the session has none. See
# `analyze` for why the dependency sits on the parameter.
@router.post("/reports", response_model=ThreatReport)
async def post_report(  # noqa: N803
    sessionId: str = Body(..., embed=True),
    claims: dict | None = Depends(require_admin),
) -> ThreatReport:
    # See `analyze`: the honeypot is only knowable through the session.
    session = await get_session(sessionId)
    if session is None:
        raise HTTPException(status_code=404, detail=f"unknown session {sessionId}")
    assert_admin_for(claims, session.honeypot_id)

    try:
        return await create_report(sessionId, actor=Actor.from_claims(claims))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
