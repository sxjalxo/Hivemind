import asyncio
from typing import Literal

from fastapi import APIRouter

from app.config import get_settings
from app.db.session import pg_health
from app.es.client import es_health
from app.serialization import CamelModel

router = APIRouter()

ServiceState = Literal["connected", "degraded", "disconnected", "running", "unknown"]


class ServiceStatus(CamelModel):
    id: str
    name: str
    state: ServiceState
    detail: str | None = None


@router.get("/status", response_model=list[ServiceStatus])
async def get_status() -> list[ServiceStatus]:
    settings = get_settings()
    (es_state, es_detail), (pg_state, pg_detail) = await asyncio.gather(
        es_health(), pg_health()
    )
    evaluator_configured = settings.byok_api_key is not None

    return [
        ServiceStatus(
            id="elasticsearch", name="Elasticsearch", state=es_state, detail=es_detail
        ),
        ServiceStatus(id="postgres", name="Postgres", state=pg_state, detail=pg_detail),
        ServiceStatus(
            id="ollama", name=f"Ollama ({settings.ollama_model})", state="unknown"
        ),
        ServiceStatus(
            id="evaluator",
            name="Cloud evaluator (BYOK)",
            state="connected" if evaluator_configured else "disconnected",
            detail=settings.byok_model if evaluator_configured else "no API key configured",
        ),
    ]
