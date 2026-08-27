from functools import lru_cache

from elasticsearch import AsyncElasticsearch

from app.config import get_settings


@lru_cache
def get_es() -> AsyncElasticsearch:
    return AsyncElasticsearch(get_settings().es_url, request_timeout=30)


async def es_health() -> tuple[str, str | None]:
    """Probe the cluster. Returns a (state, detail) pair for ServiceStatus."""
    try:
        health = await get_es().cluster.health()
    except Exception as exc:  # noqa: BLE001 - any failure means disconnected
        return "disconnected", str(exc)[:200]

    cluster_status = health.get("status", "unknown")
    state = "connected" if cluster_status in {"green", "yellow"} else "degraded"
    return state, f"cluster status: {cluster_status}"
