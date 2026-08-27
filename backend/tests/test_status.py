from fastapi.testclient import TestClient

from app.main import create_app


def test_status_returns_service_list() -> None:
    client = TestClient(create_app())
    response = client.get("/api/status")

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
