from fastapi import APIRouter

from app.models.intel import Indicator
from app.services.intel import list_indicators

router = APIRouter()


@router.get("/threat-intelligence", response_model=list[Indicator])
async def get_indicators(type: str | None = None, q: str | None = None) -> list[Indicator]:  # noqa: A002
    return await list_indicators(type_=type, q=q)
