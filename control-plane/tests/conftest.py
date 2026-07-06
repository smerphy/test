from __future__ import annotations

import os
from collections.abc import Iterator

# Ensure we use a fresh in-memory SQLite per test session.
os.environ.setdefault("PRAETOR_DATABASE_URL", "sqlite+pysqlite:///:memory:")
# The test suite runs without configured API keys / a production session
# secret, which is only permitted in explicit dev mode.
os.environ.setdefault("PRAETOR_DEV_MODE", "true")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db import Base, SessionLocal, get_engine
from app.main import create_app
from app.models import Organization


@pytest.fixture(scope="session")
def app():
    return create_app()


@pytest.fixture(autouse=True)
def _clean_db() -> Iterator[None]:
    # Reset the schema between tests for isolation.
    engine = get_engine()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    # Drop any cached encryption cipher so tests can reconfigure keys freely.
    from app.services.analytics_sink import reset_analytics_sink
    from app.services.crypto import reset_cipher
    from app.services.event_store import reset_event_sink
    from app.services.eventlog import reset_event_log
    from app.services.ratelimit import reset_limiter

    reset_cipher()
    reset_limiter()
    reset_event_log()
    reset_analytics_sink()
    reset_event_sink()
    yield
    reset_cipher()
    reset_limiter()
    reset_event_log()
    reset_analytics_sink()
    reset_event_sink()


@pytest.fixture
def session() -> Iterator[Session]:
    s = SessionLocal()
    try:
        yield s
        s.commit()
    finally:
        s.close()


@pytest.fixture
def org(session: Session) -> Organization:
    org = Organization(name="Acme", slug="acme")
    session.add(org)
    session.commit()
    return org


@pytest.fixture
def client(app, org: Organization) -> TestClient:
    c = TestClient(app)
    # Inject the org slug so the auth dependency resolves to our seeded org.
    c.headers.update({"X-Org-Slug": org.slug})
    return c
