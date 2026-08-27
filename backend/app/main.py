from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import status


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Honeypot Intelligence Platform API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api = APIRouter(prefix="/api")
    api.include_router(status.router, tags=["status"])
    app.include_router(api)
    return app


app = create_app()
