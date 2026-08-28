from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db.session import get_engine
from app.es.bootstrap import bootstrap_es
from app.es.client import get_es
from app.routers import dashboard, honeypots, logs, sessions, status


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.seed.seeder import seed, seeded_count

    await bootstrap_es()
    if await seeded_count() == 0:
        await seed()
    yield
    await get_es().close()
    await get_engine().dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Honeypot Intelligence Platform API",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api = APIRouter(prefix="/api")
    api.include_router(status.router, tags=["status"])
    api.include_router(logs.router, tags=["logs"])
    api.include_router(sessions.router, tags=["sessions"])
    api.include_router(honeypots.router, tags=["honeypots"])
    api.include_router(dashboard.router, tags=["dashboard"])
    app.include_router(api)
    return app


app = create_app()
