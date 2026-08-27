import pytest

from app.db.session import pg_health
from app.es.client import es_health


@pytest.mark.asyncio
async def test_es_health_reports_connected() -> None:
    state, detail = await es_health()
    assert state == "connected"
    assert detail is not None


@pytest.mark.asyncio
async def test_pg_health_reports_connected() -> None:
    state, _ = await pg_health()
    assert state == "connected"
