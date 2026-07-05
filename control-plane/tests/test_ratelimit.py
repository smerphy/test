"""Per-tenant rate limiting."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Organization
from app.services.ratelimit import RateLimiter
from app.settings import get_settings


def test_token_bucket_allows_burst_then_blocks() -> None:
    rl = RateLimiter()
    # capacity 2, no meaningful refill within the test.
    assert rl.check("org1", "ai", capacity=2.0, refill_per_sec=0.001) is None
    assert rl.check("org1", "ai", capacity=2.0, refill_per_sec=0.001) is None
    retry = rl.check("org1", "ai", capacity=2.0, refill_per_sec=0.001)
    assert retry is not None and retry > 0


def test_buckets_are_per_org() -> None:
    rl = RateLimiter()
    rl.check("orgA", "ai", 1.0, 0.001)
    # orgA is now empty, but orgB has its own full bucket.
    assert rl.check("orgA", "ai", 1.0, 0.001) is not None
    assert rl.check("orgB", "ai", 1.0, 0.001) is None


def test_ingest_endpoint_rate_limited(
    monkeypatch, client: TestClient, org: Organization
) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "rate_limit_ingest_per_min", 2)
    # /findings/report is an ingest-bucket endpoint.
    body = {"observation": "x"}
    assert client.post("/findings/report", json=body).status_code == 201
    assert client.post("/findings/report", json=body).status_code == 201
    blocked = client.post("/findings/report", json=body)
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_rate_limit_disabled(
    monkeypatch, client: TestClient, org: Organization
) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "rate_limit_enabled", False)
    monkeypatch.setattr(s, "rate_limit_ingest_per_min", 1)
    for _ in range(5):
        assert (
            client.post("/findings/report", json={"observation": "x"}).status_code
            == 201
        )


def test_limits_isolated_across_orgs(
    monkeypatch, app, session: Session, org: Organization
) -> None:
    rival = Organization(name="Rival", slug="rival")
    session.add(rival)
    session.commit()
    s = get_settings()
    monkeypatch.setattr(s, "rate_limit_ingest_per_min", 1)
    monkeypatch.setattr(s, "api_keys", ["acme-key", "rival-key"])
    monkeypatch.setattr(
        s, "api_key_orgs", {"acme-key": "acme", "rival-key": "rival"}
    )

    c = TestClient(app)
    c.headers.update({"X-API-Key": "acme-key", "X-Org-Slug": "acme"})
    assert c.post("/findings/report", json={"observation": "x"}).status_code == 201
    assert c.post("/findings/report", json={"observation": "x"}).status_code == 429

    # Rival org has its own bucket, unaffected by acme exhausting theirs.
    c.headers.update({"X-API-Key": "rival-key", "X-Org-Slug": "rival"})
    assert c.post("/findings/report", json={"observation": "x"}).status_code == 201
