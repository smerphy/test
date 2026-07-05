"""FastAPI app entry point."""

from __future__ import annotations

import structlog
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.db import init_schema
from app.routers import (
    alerts,
    approvals,
    audit,
    findings,
    metrics,
    org,
    policies,
    reports,
)
from app.routers import auth as auth_router
from app.settings import DEFAULT_SESSION_SECRET as _DEFAULT_SESSION_SECRET
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

    # Fail closed on insecure defaults outside dev mode: the session secret
    # signs browser auth cookies, so the built-in placeholder must never ship.
    if not settings.dev_mode and settings.session_secret == _DEFAULT_SESSION_SECRET:
        raise RuntimeError(
            "PRAETOR_SESSION_SECRET must be set to a strong random value "
            "(the built-in default signs auth cookies). Set PRAETOR_DEV_MODE=true "
            "only for local development."
        )

    app = FastAPI(
        title="Praetor Control Plane",
        version=__version__,
        description="Policy authoring, audit storage, approvals, compliance reports.",
    )

    # Signed session cookies for OAuth (browser auth). Cookies are marked
    # Secure (https_only) except in dev mode, so the auth cookie is never sent
    # over plaintext in production.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        same_site="lax",
        https_only=not settings.dev_mode,
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
    app.include_router(metrics.router)
    app.include_router(alerts.router)
    app.include_router(org.router)
    app.include_router(findings.router)
    app.include_router(auth_router.router)

    @app.middleware("http")
    async def _security_headers(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        # This is a JSON API (no first-party HTML app surface), so lock the
        # browser down hard: deny framing, forbid content sniffing, and a CSP
        # that blocks any resource loading. HSTS only outside dev (needs TLS).
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        if not settings.dev_mode:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        return response

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()


__all__ = ["app", "create_app"]
