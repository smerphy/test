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
    yield


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
