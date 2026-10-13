from fastapi import APIRouter, HTTPException

from app.models.intel import AttackerProfileOut
from app.services import reputation
from app.services.profiles import build_profile

router = APIRouter()


@router.get("/attackers/{ip}", response_model=AttackerProfileOut)
async def get_attacker(ip: str) -> AttackerProfileOut:
    profile = await build_profile(ip)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"no sessions recorded for {ip}")
    return profile



@router.get("/attackers/{ip}/reputation", response_model=reputation.Reputation)
async def get_attacker_reputation(ip: str) -> reputation.Reputation:
    # Every outcome is a 200 with a status: "not configured" and "rate limited"
    # are answers about the lookup, not failures of this API.
    return await reputation.lookup(ip)
