"""SCIM 2.0 provisioning + session management (deprovision → revoke)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Organization, User
from app.settings import get_settings


def _scim_client(monkeypatch, app, org: Organization, token: str = "scim-tok") -> TestClient:
    s = get_settings()
    monkeypatch.setattr(s, "scim_tokens", {token: org.slug})
    c = TestClient(app)
    c.headers.update({"Authorization": f"Bearer {token}"})
    return c


def test_scim_requires_valid_token(app, org: Organization) -> None:
    c = TestClient(app)
    assert c.get("/scim/v2/Users").status_code == 401
    c.headers.update({"Authorization": "Bearer nope"})
    assert c.get("/scim/v2/Users").status_code == 401


def test_scim_create_and_get(monkeypatch, app, session: Session, org: Organization) -> None:
    c = _scim_client(monkeypatch, app, org)
    r = c.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "New.User@acme.com",
            "displayName": "New User",
            "externalId": "okta-123",
            "active": True,
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["userName"] == "new.user@acme.com"
    assert body["active"] is True
    uid = body["id"]

    # Provisioned users start least-privileged.
    user = session.get(User, uid)
    assert user is not None and user.role == "viewer" and user.external_id == "okta-123"

    assert c.get(f"/scim/v2/Users/{uid}").json()["userName"] == "new.user@acme.com"


def test_scim_duplicate_conflicts(monkeypatch, app, session: Session, org: Organization) -> None:
    session.add(User(email="dup@acme.com", organization_id=org.id, role="viewer"))
    session.commit()
    c = _scim_client(monkeypatch, app, org)
    r = c.post("/scim/v2/Users", json={"userName": "dup@acme.com"})
    assert r.status_code == 409


def test_scim_filter_by_username(monkeypatch, app, session: Session, org: Organization) -> None:
    session.add_all([
        User(email="a@acme.com", organization_id=org.id, role="viewer"),
        User(email="b@acme.com", organization_id=org.id, role="viewer"),
    ])
    session.commit()
    c = _scim_client(monkeypatch, app, org)
    r = c.get('/scim/v2/Users?filter=userName eq "a@acme.com"')
    assert r.json()["totalResults"] == 1
    assert r.json()["Resources"][0]["userName"] == "a@acme.com"


def test_scim_deprovision_deactivates_and_revokes(
    monkeypatch, app, session: Session, org: Organization
) -> None:
    u = User(email="gone@acme.com", organization_id=org.id, role="viewer")
    session.add(u)
    session.commit()
    epoch0 = u.session_epoch
    c = _scim_client(monkeypatch, app, org)

    # PATCH active=false → deactivated + session epoch bumped (revoked).
    r = c.patch(
        f"/scim/v2/Users/{u.id}",
        json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
    )
    assert r.status_code == 200
    assert r.json()["active"] is False
    session.refresh(u)
    assert u.active is False
    assert u.session_epoch == epoch0 + 1


def test_scim_delete_soft_deactivates(
    monkeypatch, app, session: Session, org: Organization
) -> None:
    u = User(email="del@acme.com", organization_id=org.id, role="viewer")
    session.add(u)
    session.commit()
    c = _scim_client(monkeypatch, app, org)
    assert c.delete(f"/scim/v2/Users/{u.id}").status_code == 204
    session.refresh(u)
    # Soft delete: still present (audit trail), but inactive.
    assert u.active is False


def test_revoke_sessions_endpoint(client: TestClient, session: Session, org: Organization) -> None:
    u = User(email="member@acme.com", organization_id=org.id, role="analyst")
    session.add(u)
    session.commit()
    before = u.session_epoch
    r = client.post(f"/users/{u.id}/revoke-sessions")
    assert r.status_code == 200
    session.refresh(u)
    assert u.session_epoch == before + 1
