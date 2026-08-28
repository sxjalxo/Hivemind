from fastapi import APIRouter

from app.models.dashboard import DashboardData
from app.services.dashboard import build_dashboard

router = APIRouter()


@router.get("/dashboard", response_model=DashboardData)
async def get_dashboard(range: str = "24h") -> DashboardData:  # noqa: A002
    return await build_dashboard(range)
