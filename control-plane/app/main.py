"""FastAPI app entry point."""

from __future__ import annotations

import structlog
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.db import init_schema
from app.routers import approvals, audit, policies, reports
from app.routers import auth as auth_router
from app.settings import get_settings


def _configure_logging() -> None:
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
    )


def create_app() -> FastAPI:
    _configure_logging()
    settings = get_settings()
    app = FastAPI(
        title="Praetor Control Plane",
        version=__version__,
        description="Policy authoring, audit storage, approvals, compliance reports.",
    )

    # Signed session cookies for OAuth (browser auth).
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        same_site="lax",
        https_only=False,  # set True behind TLS termination in prod
    )

    # In production the schema is managed by Alembic. The convenience
    # init_schema() here makes test runs and `uvicorn app.main:app`
    # one-command launchable against an empty database.
    if settings.database_url.startswith("sqlite"):
        init_schema()

    app.include_router(policies.router)
    app.include_router(audit.router)
    app.include_router(approvals.router)
    app.include_router(reports.router)
    app.include_router(auth_router.router)

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()


__all__ = ["app", "create_app"]
