from fastapi import APIRouter

from app.config import get_settings
from app.serialization import CamelModel

router = APIRouter()


class ServiceStatus(CamelModel):
    id: str
    name: str
    state: str
    detail: str | None = None


@router.get("/status", response_model=list[ServiceStatus])
async def get_status() -> list[ServiceStatus]:
    settings = get_settings()
    evaluator_configured = settings.byok_api_key is not None
    return [
        ServiceStatus(id="elasticsearch", name="Elasticsearch", state="unknown"),
        ServiceStatus(id="postgres", name="Postgres", state="unknown"),
        ServiceStatus(
            id="ollama",
            name=f"Ollama ({settings.ollama_model})",
            state="unknown",
        ),
        ServiceStatus(
            id="evaluator",
            name="Cloud evaluator (BYOK)",
            state="connected" if evaluator_configured else "disconnected",
            detail=settings.byok_model if evaluator_configured else "no API key configured",
        ),
    ]
