"""Immutable audit anchoring + tamper verification + export."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditEvent, Organization
from app.services.anchoring import create_anchor, verify_latest
from app.settings import get_settings


def _audit(
    session: Session,
    org: Organization,
    agent: str,
    sess: str,
    seq: int,
    h: str,
) -> AuditEvent:
    ev = AuditEvent(
        organization_id=org.id,
        seq=seq,
        timestamp=datetime.now(UTC),
        agent_id=agent,
        session_id=sess,
        tool_name="t",
        tool_arguments={},
        decision="allow",
        reason="r",
        matched_policy_id=None,
        context={},
        evaluator_version="0.1.0",
        prev_hash="0" * 64,
        hash=h,
    )
    session.add(ev)
    return ev


def test_anchor_and_verify_clean(session: Session, org: Organization) -> None:
    _audit(session, org, "a1", "s1", 0, "h1a")
    _audit(session, org, "a1", "s1", 1, "h1b")
    _audit(session, org, "a2", "s2", 0, "h2a")
    session.commit()

    anchor = create_anchor(session, org)
    session.commit()
    assert anchor.chain_count == 2
    assert anchor.event_count == 3
    assert anchor.prev_anchor_hash == "0" * 64
    assert len(anchor.root) == 64

    v = verify_latest(session, org.id)
    assert v["tampered"] is False
    assert v["chains_checked"] == 2


def test_verify_detects_hash_tamper(session: Session, org: Organization) -> None:
    e = _audit(session, org, "a1", "s1", 0, "original")
    session.commit()
    create_anchor(session, org)
    session.commit()

    e.hash = "tampered-value"
    session.commit()
    v = verify_latest(session, org.id)
    assert v["tampered"] is True
    assert v["mismatches"][0]["reason"] == "hash_mismatch"


def test_verify_detects_deleted_head(session: Session, org: Organization) -> None:
    e = _audit(session, org, "a1", "s1", 0, "h")
    session.commit()
    create_anchor(session, org)
    session.commit()

    session.delete(e)
    session.commit()
    v = verify_latest(session, org.id)
    assert v["tampered"] is True
    assert v["mismatches"][0]["reason"] == "missing"


def test_anchors_chain_together(session: Session, org: Organization) -> None:
    _audit(session, org, "a1", "s1", 0, "h1")
    session.commit()
    first = create_anchor(session, org)
    session.commit()
    _audit(session, org, "a1", "s1", 1, "h2")
    session.commit()
    second = create_anchor(session, org)
    session.commit()
    assert second.prev_anchor_hash == first.anchor_hash
    # Appending an event (higher seq) does not invalidate the first anchor.
    assert verify_latest(session, org.id)["tampered"] is False


def test_no_anchor_yet(session: Session, org: Organization) -> None:
    v = verify_latest(session, org.id)
    assert v["anchored"] is False
    assert v["tampered"] is False


# --- endpoints --------------------------------------------------------------
def test_anchor_endpoints(client: TestClient, session: Session, org: Organization) -> None:
    _audit(session, org, "a1", "s1", 0, "h1")
    session.commit()

    r = client.post("/audit/anchor")
    assert r.status_code == 200
    assert r.json()["chain_count"] == 1

    assert len(client.get("/audit/anchors").json()) == 1
    assert client.get("/audit/verify").json()["tampered"] is False

    export = client.get("/audit/export")
    assert export.status_code == 200
    assert "X-Ephorate-Audit-Root" in export.headers
    assert export.text.strip()  # one NDJSON line


def test_anchor_requires_admin(monkeypatch, app, org: Organization) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["an"])
    monkeypatch.setattr(s, "api_key_orgs", {"an": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"an": "analyst"})
    c = TestClient(app)
    c.headers.update({"X-API-Key": "an", "X-Org-Slug": "acme"})
    assert c.post("/audit/anchor").status_code == 403
    assert c.get("/audit/verify").status_code == 403
    assert c.get("/audit/export").status_code == 403
