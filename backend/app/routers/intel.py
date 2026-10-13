from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from app.models.intel import Indicator, IocExport
from app.routers.limits import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from app.services import virustotal
from app.services.intel import get_indicator, list_indicators
from app.services.ioc_export import build_export

router = APIRouter()


@router.get("/threat-intelligence", response_model=list[Indicator])
async def get_indicators(  # noqa: A002
    type: str | None = None,
    q: str | None = None,
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
) -> list[Indicator]:
    return await list_indicators(type_=type, q=q, limit=limit)


@router.get("/threat-intelligence/export", response_model=IocExport)
async def export_indicators(
    format: Literal["stix", "misp", "blocklist"] = "stix",
) -> IocExport:
    # Every indicator, unpaged: an export is the whole list or it is misleading.
    # Threat intelligence is deliberately unscoped (see `auth.role_for`), as the
    # list route above is.
    return build_export(format, await list_indicators())


@router.get(
    "/threat-intelligence/{indicator_id}/virustotal",
    response_model=virustotal.VirusTotalVerdict,
)
async def get_virustotal_verdict(indicator_id: str) -> virustotal.VirusTotalVerdict:
    # By id, so only an indicator this system extracted can be looked up: the
    # key is never a general-purpose VirusTotal proxy. See the service docstring.
    indicator = await get_indicator(indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail=f"unknown indicator {indicator_id}")
    return await virustotal.lookup(indicator)
