from fastapi import APIRouter, HTTPException

from app.models.event import HoneypotEvent
from app.models.session import AttackSession, SessionTimelineEvent
from app.services import session_builder

router = APIRouter()


@router.get("/sessions", response_model=list[AttackSession])
async def get_sessions(
    risk: str | None = None,
    honeypotId: str | None = None,  # noqa: N803 - query param is camelCase
    q: str | None = None,
) -> list[AttackSession]:
    return await session_builder.list_sessions(risk=risk, honeypot_id=honeypotId, q=q)


@router.get("/sessions/{session_id}", response_model=AttackSession)
async def get_session(session_id: str) -> AttackSession:
    session = await session_builder.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"unknown session {session_id}")
    return session


@router.get("/sessions/{session_id}/events", response_model=list[HoneypotEvent])
async def get_session_events(session_id: str) -> list[HoneypotEvent]:
    return await session_builder.get_session_events(session_id)


@router.get("/sessions/{session_id}/timeline", response_model=list[SessionTimelineEvent])
async def get_session_timeline(session_id: str) -> list[SessionTimelineEvent]:
    return await session_builder.build_timeline(session_id)
