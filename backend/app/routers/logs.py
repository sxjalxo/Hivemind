from fastapi import APIRouter, Depends

from app.es.queries import search_logs
from app.models.event import HoneypotEvent, LogQuery, Paginated

router = APIRouter()


@router.get("/logs", response_model=Paginated[HoneypotEvent])
async def get_logs(query: LogQuery = Depends()) -> Paginated[HoneypotEvent]:
    return await search_logs(query)
