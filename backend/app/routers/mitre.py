from fastapi import APIRouter

from app.models.mitre import MitreCoverage
from app.services.coverage import build_coverage

router = APIRouter()


@router.get("/mitre", response_model=MitreCoverage)
async def get_mitre(sessionId: str | None = None) -> MitreCoverage:  # noqa: N803
    return await build_coverage(session_id=sessionId)
