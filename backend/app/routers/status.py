import asyncio
from typing import Literal

from fastapi import APIRouter

from app.config import get_settings
from app.db.session import pg_health
from app.es.client import es_health
from app.seed.seeder import seeded_count
from app.serialization import CamelModel
from app.services.evaluation.container import docker_health
from app.services.llm.ollama import ollama_health

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
    (
        (es_state, es_detail),
        (pg_state, pg_detail),
        (ol_state, ol_detail),
        (docker_state, docker_detail),
    ) = await asyncio.gather(
        es_health(),
        pg_health(),
        ollama_health(),
        # Gathered with the rest rather than awaited after them: this shells
        # out to the docker CLI, and run serially it would add its latency to
        # a dashboard that polls.
        docker_health(settings.evaluation_container_name),
    )
    evaluator_configured = settings.byok_api_key is not None
    seeded = await seeded_count()

    return [
        ServiceStatus(
            id="elasticsearch", name="Elasticsearch", state=es_state, detail=es_detail
        ),
        ServiceStatus(id="postgres", name="Postgres", state=pg_state, detail=pg_detail),
        ServiceStatus(
            id="ollama",
            name=f"Ollama ({settings.ollama_model})",
            state=ol_state,
            detail=ol_detail,
        ),
        ServiceStatus(
            id="evaluator",
            name="Cloud evaluator (BYOK)",
            state="connected" if evaluator_configured else "disconnected",
            detail=settings.byok_model if evaluator_configured else "no API key configured",
        ),
        ServiceStatus(
            id="authentication",
            name="Authentication (Clerk)",
            # `disconnected` rather than a cheerier state when it is off: an
            # open API is a real condition an operator should see on the
            # dashboard, not an absence to gloss over. Same convention the
            # evaluator row uses for a missing BYOK key.
            state="connected" if settings.auth_enabled else "disconnected",
            detail=(
                settings.clerk_issuer
                if settings.auth_enabled
                else "OPEN — every route answers any caller; set CLERK_ISSUER"
            ),
        ),
        ServiceStatus(
            id="docker",
            # Named for what it gates rather than for the daemon, because the
            # question an operator has is "can I evaluate", not "is Docker up".
            name="Evaluation (Docker)",
            state=docker_state,
            detail=docker_detail,
        ),
        ServiceStatus(
            id="seed-corpus",
            name="Seeded corpus",
            state="running" if seeded else "unknown",
            detail=f"{seeded} seeded events" if seeded else "no seeded events",
        ),
    ]
