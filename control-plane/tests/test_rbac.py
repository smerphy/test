"""RBAC: role ordering, per-endpoint enforcement, API-key role scoping,
and owner-only user/role management."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth import Principal, current_principal
from app.models import Organization, Role, User
from app.rbac import role_at_least, role_level
from app.settings import get_settings


def test_role_ordering() -> None:
    assert role_at_least(Role.OWNER, Role.ADMIN)
    assert role_at_least(Role.ADMIN, Role.ADMIN)
    assert role_at_least(Role.ANALYST, Role.VIEWER)
    assert not role_at_least(Role.ANALYST, Role.ADMIN)
    assert not role_at_least(Role.VIEWER, Role.ANALYST)
    # String inputs are accepted; unknown roles collapse to least privilege.
    assert role_at_least("owner", "viewer")
    assert role_level("bogus") == 0
    assert not role_at_least("bogus", Role.ANALYST)


@pytest.fixture
def _overrides(app) -> Iterator[None]:
    yield
    app.dependency_overrides.clear()


def _act_as(app, org: Organization, role: Role) -> TestClient:
    app.dependency_overrides[current_principal] = lambda: Principal(
        org=org, role=role, kind="user", user_id="u-test"
    )
    return TestClient(app)


def test_viewer_can_read_but_not_mutate(
    app, org: Organization, _overrides: None
) -> None:
    c = _act_as(app, org, Role.VIEWER)
    # Reads are allowed for viewers.
    assert c.get("/findings").status_code == 200
    # Mutations are not.
    assert c.post("/findings/run").status_code == 403
    assert c.post(
        "/quarantines", json={"agent_id": "a1", "reason": "x"}
    ).status_code == 403


def test_analyst_can_run_ops_but_not_config(
    app, org: Organization, _overrides: None
) -> None:
    c = _act_as(app, org, Role.ANALYST)
    # Ops actions: allowed.
    assert c.post("/findings/run").status_code == 200
    assert c.post(
        "/quarantines", json={"agent_id": "a1", "reason": "x"}
    ).status_code == 201
    # Config actions: denied (need admin).
    assert c.patch("/org", json={}).status_code == 403


def test_admin_can_change_config(
    app, org: Organization, _overrides: None
) -> None:
    c = _act_as(app, org, Role.ADMIN)
    assert c.patch("/org", json={"auto_quarantine": True}).status_code == 200


def test_api_key_role_scoping(monkeypatch, app, org: Organization) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["ro-key", "rw-key"])
    monkeypatch.setattr(
        s, "api_key_orgs", {"ro-key": "acme", "rw-key": "acme"}
    )
    monkeypatch.setattr(
        s, "api_key_roles", {"ro-key": "viewer", "rw-key": "admin"}
    )

    c = TestClient(app)
    # Read-only key: reads succeed, writes are forbidden.
    c.headers.update({"X-API-Key": "ro-key", "X-Org-Slug": "acme"})
    assert c.get("/findings").status_code == 200
    assert c.post("/findings/run").status_code == 403

    # Admin key: writes succeed.
    c.headers.update({"X-API-Key": "rw-key", "X-Org-Slug": "acme"})
    assert c.post("/findings/run").status_code == 200


def test_api_key_default_role_governs_unlisted_keys(
    monkeypatch, app, org: Organization
) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["k"])
    monkeypatch.setattr(s, "api_key_orgs", {"k": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {})
    monkeypatch.setattr(s, "api_key_default_role", "viewer")

    c = TestClient(app)
    c.headers.update({"X-API-Key": "k", "X-Org-Slug": "acme"})
    assert c.get("/findings").status_code == 200
    assert c.post("/findings/run").status_code == 403


def test_first_user_is_owner_rest_are_viewers(session: Session) -> None:
    from app.routers.auth import _upsert_user

    a = _upsert_user(session, email="alice@acmecorp.com", name="Alice")
    b = _upsert_user(session, email="bob@acmecorp.com", name="Bob")
    session.commit()
    # Same corporate org: the founder owns it, but teammates who auto-join a
    # shared corporate tenant default to least-privilege `viewer` (an owner
    # elevates them via /users). Auto-granting admin would be a privilege
    # escalation for anyone who controls a corporate-domain mailbox.
    assert a.organization_id == b.organization_id
    assert a.role == Role.OWNER.value
    assert b.role == Role.VIEWER.value


def test_users_me_404_for_api_key(client: TestClient) -> None:
    # The dev-mode API-key path has no associated User row.
    assert client.get("/users/me").status_code == 404


def test_whoami_reports_role_for_api_key(
    monkeypatch, app, org: Organization
) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["ro-key"])
    monkeypatch.setattr(s, "api_key_orgs", {"ro-key": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"ro-key": "viewer"})

    c = TestClient(app)
    c.headers.update({"X-API-Key": "ro-key", "X-Org-Slug": "acme"})
    r = c.get("/whoami")
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "api_key"
    assert body["role"] == "viewer"
    assert body["organization_slug"] == "acme"
    assert body["user_id"] is None


def test_owner_manages_roles_and_last_owner_is_protected(
    monkeypatch, app, session: Session, org: Organization
) -> None:
    owner = User(email="owner@acme.com", organization_id=org.id, role="owner")
    analyst = User(
        email="analyst@acme.com", organization_id=org.id, role="analyst"
    )
    session.add_all([owner, analyst])
    session.commit()

    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["owner-key", "analyst-key"])
    monkeypatch.setattr(
        s, "api_key_orgs", {"owner-key": "acme", "analyst-key": "acme"}
    )
    monkeypatch.setattr(
        s, "api_key_roles", {"owner-key": "owner", "analyst-key": "analyst"}
    )

    c = TestClient(app)

    # Analyst may not list members (admin) or change roles (owner).
    c.headers.update({"X-API-Key": "analyst-key", "X-Org-Slug": "acme"})
    assert c.get("/users").status_code == 403
    assert c.patch(f"/users/{analyst.id}", json={"role": "admin"}).status_code == 403

    # Owner can list and promote.
    c.headers.update({"X-API-Key": "owner-key", "X-Org-Slug": "acme"})
    listed = c.get("/users")
    assert listed.status_code == 200
    assert len(listed.json()) == 2

    promoted = c.patch(f"/users/{analyst.id}", json={"role": "admin"})
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "admin"

    # Demoting the last remaining owner is refused.
    conflict = c.patch(f"/users/{owner.id}", json={"role": "admin"})
    assert conflict.status_code == 409
