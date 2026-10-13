import asyncio
from typing import Literal

from elasticsearch import NotFoundError
from fastapi import APIRouter

from app.config import get_settings
from app.db.session import pg_health
from app.es.client import es_health, get_es
from app.seed.seeder import seeded_count
from app.serialization import CamelModel
from app.services.evaluation.container import docker_health
from app.services.llm.ollama import ollama_health

router = APIRouter()

ServiceState = Literal["connected", "degraded", "disconnected", "running", "unknown"]

# Where Filebeat puts events Elasticsearch refused (see the
# `non_indexable_policy` stanza in infra/filebeat/filebeat.yml). Filebeat's
# default is to DROP them, so this index is the only record they existed.
REJECTED_EVENTS_INDEX = "hivemind-rejected-events"


async def rejected_events_health() -> tuple[ServiceState, str]:
    """How many captured events the index mapping has refused.

    No index is zero rejections: Filebeat creates it on the first one. Any
    other failure is `unknown`, never "none" -- a count we could not read is
    not a clean bill.
    """
    try:
        count = (await get_es().count(index=REJECTED_EVENTS_INDEX))["count"]
    except NotFoundError:
        return "running", "0 events rejected"
    except Exception as exc:  # noqa: BLE001
        return "unknown", f"could not count rejected events: {str(exc)[:120]}"
    if count:
        return (
            "degraded",
            (
                f"{count} captured events refused by the index mapping; the originals "
                f"are kept in {REJECTED_EVENTS_INDEX}"
            ),
        )
    return "running", "0 events rejected"


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
        (rejected_state, rejected_detail),
    ) = await asyncio.gather(
        es_health(),
        pg_health(),
        ollama_health(),
        # Gathered with the rest rather than awaited after them: this shells
        # out to the docker CLI, and run serially it would add its latency to
        # a dashboard that polls.
        docker_health(settings.evaluation_container_name),
        rejected_events_health(),
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
        ServiceStatus(
            id="reputation",
            name="Reputation (AbuseIPDB)",
            # Configured or not -- never a live call: this page polls, and a
            # status check must not spend the lookup quota.
            state="connected" if settings.abuseipdb_api_key else "disconnected",
            detail=(
                "API key configured; lookups on attacker pages"
                if settings.abuseipdb_api_key
                else "not configured (optional): set ABUSEIPDB_API_KEY"
            ),
        ),
        ServiceStatus(
            id="virustotal",
            name="VirusTotal",
            # Configured or not, never a live call: the free tier is 4 a minute.
            state="connected" if settings.virustotal_api_key else "disconnected",
            detail=(
                "API key configured; on-demand lookups on Threat Intelligence"
                if settings.virustotal_api_key
                else "not configured (optional): set VIRUSTOTAL_API_KEY"
            ),
        ),
        ServiceStatus(
            id="rejected-events",
            name="Rejected events",
            state=rejected_state,
            detail=rejected_detail,
        ),
    ]
