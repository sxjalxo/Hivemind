from fastapi import APIRouter, Query

from app.models.intel import Indicator
from app.routers.limits import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from app.services.intel import list_indicators

router = APIRouter()


@router.get("/threat-intelligence", response_model=list[Indicator])
async def get_indicators(  # noqa: A002
    type: str | None = None,
    q: str | None = None,
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
) -> list[Indicator]:
    return await list_indicators(type_=type, q=q, limit=limit)
