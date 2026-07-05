"""Audit-the-auditors: access logging of sensitive reads/exports."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.models import AccessLog, Organization
from app.settings import get_settings


def test_reads_are_logged(client: TestClient, session, org: Organization) -> None:
    assert client.get("/findings").status_code == 200
    assert client.get("/audit/events").status_code == 200
    logs = session.query(AccessLog).filter_by(organization_id=org.id).all()
    resources = {log.resource for log in logs}
    assert {"findings", "audit"} <= resources
    for log in logs:
        assert log.actor_kind == "api_key"
        assert log.action in {"read", "export"}


def test_access_log_endpoint_lists_and_filters(
    client: TestClient, org: Organization
) -> None:
    client.get("/findings")
    client.get("/audit/events")
    r = client.get("/access-log")
    assert r.status_code == 200
    assert len(r.json()) >= 2
    only = client.get("/access-log?resource=findings").json()
    assert only and all(e["resource"] == "findings" for e in only)


def test_viewing_access_log_is_not_itself_logged(
    client: TestClient, session, org: Organization
) -> None:
    client.get("/access-log")
    # The access-log viewer is not part of the logged surface (would recurse).
    assert (
        session.query(AccessLog).filter_by(resource="access-log").count() == 0
    )


def test_access_log_requires_admin(
    monkeypatch, app, org: Organization
) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["an"])
    monkeypatch.setattr(s, "api_key_orgs", {"an": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"an": "analyst"})
    c = TestClient(app)
    c.headers.update({"X-API-Key": "an", "X-Org-Slug": "acme"})
    assert c.get("/access-log").status_code == 403


def test_export_action_recorded(
    client: TestClient, session, org: Organization
) -> None:
    # Timeline read is logged under the investigate resource.
    client.get("/timeline/session/s1")
    log = (
        session.query(AccessLog)
        .filter_by(organization_id=org.id, resource="investigate")
        .first()
    )
    assert log is not None
