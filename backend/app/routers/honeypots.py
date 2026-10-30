from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import assert_can_read, denied_honeypots, denies_everything, require_user
from app.models.honeypot import Honeypot
from app.models.sensor import SensorProfile, SensorTechniques, SensorTraffic
from app.services import sensors
from app.services.dashboard import list_honeypots

router = APIRouter()


@router.get("/honeypots", response_model=list[Honeypot])
async def get_honeypots(claims: dict | None = Depends(require_user)) -> list[Honeypot]:
    # Scoped like the session list: a sensor the profile route hides must not be listed.
    if denies_everything(claims):
        return []
    denied = denied_honeypots(claims)
    return [h for h in await list_honeypots() if h.id not in denied]


@router.get("/honeypots/{honeypot_id}", response_model=SensorProfile)
async def get_honeypot(
    honeypot_id: str, claims: dict | None = Depends(require_user)
) -> SensorProfile:
    assert_can_read(claims, honeypot_id)
    profile = await sensors.get_profile(honeypot_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="not found")
    return profile


@router.get("/honeypots/{honeypot_id}/traffic", response_model=SensorTraffic)
async def get_honeypot_traffic(
    honeypot_id: str,
    days: int = Query(30, ge=1, le=90),
    claims: dict | None = Depends(require_user),
) -> SensorTraffic:
    assert_can_read(claims, honeypot_id)
    traffic = await sensors.get_traffic(honeypot_id, days)
    if traffic is None:
        raise HTTPException(status_code=404, detail="not found")
    return traffic


@router.get("/honeypots/{honeypot_id}/techniques", response_model=SensorTechniques)
async def get_honeypot_techniques(
    honeypot_id: str,
    days: int = Query(30, ge=1, le=90),
    claims: dict | None = Depends(require_user),
) -> SensorTechniques:
    assert_can_read(claims, honeypot_id)
    techniques = await sensors.get_techniques(honeypot_id, days)
    if techniques is None:
        raise HTTPException(status_code=404, detail="not found")
    return techniques
