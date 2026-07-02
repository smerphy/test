"""SQLAlchemy engine + session management.

Synchronous SQLAlchemy 2.0. The MVP uses sync because FastAPI handles
the thread-pool offload for sync DB calls cleanly, and the rest of the
stack (Alembic, psycopg) has the most mature sync story today. Async
is a future swap behind the same session dependency.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Final

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.settings import get_settings

_settings = get_settings()


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _build_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        # In-memory SQLite needs StaticPool so every connection shares
        # the same database. check_same_thread off for FastAPI's
        # thread-pool offload.
        return create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
    return create_engine(url, future=True)


_engine: Final[Engine] = _build_engine(_settings.database_url)

SessionLocal: Final[sessionmaker[Session]] = sessionmaker(
    bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False
)


def get_engine() -> Engine:
    return _engine


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a per-request session, commits on success."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_schema() -> None:
    """Dev / test convenience: create all tables. Production uses Alembic."""
    # Import models so SQLAlchemy registers them on `Base.metadata`.
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=_engine)


__all__ = ["Base", "SessionLocal", "get_engine", "get_session", "init_schema"]
