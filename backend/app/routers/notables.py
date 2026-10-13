from fastapi import APIRouter, Depends, Query

from app.auth import denied_honeypots, denies_everything, require_user
from app.models.notable import Notable
from app.services.notables import list_notables

router = APIRouter()


@router.get("/notables", response_model=list[Notable])
async def get_notables(
    days: int = Query(7, ge=1, le=30),
    claims: dict | None = Depends(require_user),
) -> list[Notable]:
    # Built from per-honeypot sessions and analyses, so scoped like them.
    if denies_everything(claims):
        return []
    return await list_notables(days=days, deny_honeypots=denied_honeypots(claims))
