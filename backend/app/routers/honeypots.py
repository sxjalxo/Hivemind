from fastapi import APIRouter

from app.models.honeypot import Honeypot
from app.services.dashboard import list_honeypots

router = APIRouter()


@router.get("/honeypots", response_model=list[Honeypot])
async def get_honeypots() -> list[Honeypot]:
    return await list_honeypots()
