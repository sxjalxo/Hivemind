from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import assert_can_read, denied_honeypots, denies_everything, require_user
from app.models.event import HoneypotEvent
from app.models.session import AttackSession, SessionTimelineEvent
from app.routers.limits import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from app.services import session_builder

router = APIRouter()

# Read scoping, per `auth.role_for`. These four routes serve ONE honeypot's
# operational record, so a caller denied that sensor must not see them. The
# detail routes resolve the honeypot from the session first and then answer
# 404, never 403, so the status code cannot be used to enumerate which
# sessions a hidden sensor has -- see `assert_can_read`.


@router.get("/sessions", response_model=list[AttackSession])
async def get_sessions(
    risk: str | None = None,
    honeypotId: str | None = None,  # noqa: N803 - query param is camelCase
    q: str | None = None,
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    claims: dict | None = Depends(require_user),
) -> list[AttackSession]:
    if denies_everything(claims):
        return []
    return await session_builder.list_sessions(
        risk=risk,
        honeypot_id=honeypotId,
        q=q,
        limit=limit,
        deny_honeypots=denied_honeypots(claims),
    )


@router.get("/sessions/{session_id}", response_model=AttackSession)
async def get_session(
    session_id: str, claims: dict | None = Depends(require_user)
) -> AttackSession:
    session = await session_builder.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"unknown session {session_id}")
    assert_can_read(claims, session.honeypot_id)
    return session


@router.get("/sessions/{session_id}/events", response_model=list[HoneypotEvent])
async def get_session_events(
    session_id: str, claims: dict | None = Depends(require_user)
) -> list[HoneypotEvent]:
    await _assert_session_readable(session_id, claims)
    return await session_builder.get_session_events(session_id)


@router.get("/sessions/{session_id}/timeline", response_model=list[SessionTimelineEvent])
async def get_session_timeline(
    session_id: str, claims: dict | None = Depends(require_user)
) -> list[SessionTimelineEvent]:
    await _assert_session_readable(session_id, claims)
    return await session_builder.build_timeline(session_id)


async def _assert_session_readable(session_id: str, claims: dict | None) -> None:
    """Resolve a session's honeypot, then apply the caller's read scope.

    An unknown session is left alone: both handlers already answer an empty
    list for one, and turning that into a 404 here would change a response
    these routes have always given.
    """
    session = await session_builder.get_session(session_id)
    if session is not None:
        assert_can_read(claims, session.honeypot_id)
