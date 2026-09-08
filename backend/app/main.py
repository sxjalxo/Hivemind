import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db.session import get_engine
from app.es.bootstrap import bootstrap_es
from app.es.client import get_es
from app.routers import (
    analysis,
    analyze,
    attackers,
    dashboard,
    evaluation,
    events,
    honeypots,
    intel,
    logs,
    mitre,
    reports,
    sessions,
    status,
)
from app.services.evaluation import runs

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.seed.seeder import seed, seeded_count

    await bootstrap_es()
    if await seeded_count() == 0:
        await seed()

    # A process killed mid-run leaves `status=running` with nothing left in
    # the system to finish it, and that honeypot is then refused a new
    # evaluation. `start_run` only ever reconciles the honeypot it was called
    # for -- which is the run the orphan is blocking -- so the sweep has to
    # happen here, with no argument, before any request is served. Only rows
    # too old to still be in progress are touched, so nothing live is
    # disturbed. Logged rather than fatal: failing to clean up is not a
    # reason to refuse to serve reads, but it is never silent either.
    try:
        await runs.reconcile_stale_runs()
    except Exception:  # noqa: BLE001
        logger.exception("could not reconcile stale evaluation runs at startup")

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
    api.include_router(analyze.router, tags=["analysis"])
    api.include_router(analysis.router, tags=["analysis"])
    api.include_router(intel.router, tags=["intel"])
    api.include_router(attackers.router, tags=["intel"])
    api.include_router(mitre.router, tags=["mitre"])
    api.include_router(reports.router, tags=["reports"])
    api.include_router(events.router, tags=["events"])
    api.include_router(evaluation.router, tags=["evaluation"])
    app.include_router(api)
    return app


app = create_app()
