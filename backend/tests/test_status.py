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


# ---------------------------------------------------------------------------
# The Docker row.
#
# It exists because "evaluation is unavailable" was otherwise discoverable
# only by starting a run: the reset fails as a PRECONDITION, so the run never
# gets a row and the detail page waits out its grace window before saying it
# has no record. That is the containerised backend's ordinary state, since it
# deliberately does not mount the daemon socket.
#
# The three states must stay distinct. "No daemon" and "that container is not
# there" have different fixes, and neither may read as working.


@pytest.mark.parametrize(
    "message",
    [
        (
            "docker inspect failed with exit code 1: Cannot connect to the Docker "
            "daemon at unix:///var/run/docker.sock. Is the docker daemon running?"
        ),
        # Docker Desktop on Windows, which says neither of the phrases above.
        # This exact wording reported `degraded` until it was checked against a
        # genuinely stopped daemon.
        (
            "docker inspect failed with exit code 1: failed to connect to the docker "
            "API at npipe:////./pipe/dockerDesktopLinuxEngine"
        ),
        # The binary is not installed at all.
        "could not run 'docker': [Errno 2] No such file or directory",
    ],
)
async def test_an_unreachable_daemon_reads_as_disconnected(monkeypatch, message) -> None:
    from app.services.evaluation import container

    async def _fail(argv, *, timeout_seconds):
        raise container.ContainerExecError(message)

    monkeypatch.setattr(container, "run", _fail)
    state, detail = await container.docker_health("hivemind-cowrie-1")

    assert state == "disconnected"
    # The operator has to be told BOTH halves: what stopped working, and what
    # did not. Without the second, an open dashboard reads as a broken install.
    assert "evaluation" in detail.lower()
    assert "analysis is unaffected" in detail.lower()


async def test_a_missing_container_is_degraded_not_disconnected(monkeypatch) -> None:
    # The daemon answered. That is a different problem from having no Docker
    # access, and it must not be reported as one -- the fix is to start the
    # honeypot, not to change how the backend is deployed.
    from app.services.evaluation import container

    async def _fail(argv, *, timeout_seconds):
        raise container.ContainerExecError(
            "docker inspect failed with exit code 1: "
            "Error: No such object: hivemind-cowrie-1"
        )

    monkeypatch.setattr(container, "run", _fail)
    state, detail = await container.docker_health("hivemind-cowrie-1")

    assert state == "degraded"
    assert "hivemind-cowrie-1" in detail


async def test_an_unrecognised_failure_never_reads_as_connected(monkeypatch) -> None:
    # The daemon-detection is substring matching over the CLI's own wording,
    # which changes between versions and platforms. A phrasing this does not
    # know must still not be reported as a working evaluation path.
    from app.services.evaluation import container

    async def _fail(argv, *, timeout_seconds):
        raise container.ContainerExecError("something nobody has seen before")

    monkeypatch.setattr(container, "run", _fail)
    state, _ = await container.docker_health("hivemind-cowrie-1")

    assert state != "connected"


async def test_a_working_daemon_reads_as_connected(monkeypatch) -> None:
    from app.services.evaluation import container

    async def _ok(argv, *, timeout_seconds):
        assert argv[:2] == ["docker", "inspect"], "the probe must stay a read-only verb"
        return b"true\n"

    monkeypatch.setattr(container, "run", _ok)
    state, detail = await container.docker_health("hivemind-cowrie-1")

    assert state == "connected"
    assert detail == "hivemind-cowrie-1"
