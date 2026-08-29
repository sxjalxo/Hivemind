from fastapi import APIRouter, HTTPException

from app.models.intel import AttackerProfileOut
from app.services.profiles import build_profile

router = APIRouter()


@router.get("/attackers/{ip}", response_model=AttackerProfileOut)
async def get_attacker(ip: str) -> AttackerProfileOut:
    profile = await build_profile(ip)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"no sessions recorded for {ip}")
    return profile
