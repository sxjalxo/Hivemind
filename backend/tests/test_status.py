import httpx
import pytest
from pydantic import ValidationError

from app.main import create_app
from app.routers.status import ServiceStatus


def test_service_status_rejects_invalid_state() -> None:
    with pytest.raises(ValidationError):
        ServiceStatus(id="elasticsearch", name="Elasticsearch", state="exploded")


@pytest.mark.asyncio
async def test_status_returns_service_list() -> None:
    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/status")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)

    ids = {item["id"] for item in body}
    assert {"elasticsearch", "postgres", "ollama"} <= ids

    for item in body:
        assert set(item) >= {"id", "name", "state"}
        assert item["state"] in {
            "connected",
            "degraded",
            "disconnected",
            "running",
            "unknown",
        }
