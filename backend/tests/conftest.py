import pytest_asyncio

from app.db.session import get_engine
from app.es.bootstrap import bootstrap_es
from app.es.client import get_es


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _es_lifecycle():
    await bootstrap_es()
    yield
    await get_es().close()
    await get_engine().dispose()
