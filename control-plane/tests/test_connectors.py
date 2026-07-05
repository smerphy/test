"""Notification connectors: per-vendor payloads, gating, CRUD, secrets, RBAC."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    NotificationConnector,
    Organization,
)
from app.services.crypto import unseal
from app.services.notify_connectors import deliver_one, dispatch_finding
from app.settings import get_settings


def _capture() -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(202, json={"ok": True})

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def _finding(org: Organization, severity: str = "critical") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        organization_id=org.id,
        rule_id="r",
        title="exfil detected",
        severity=severity,
        category="data_exfil",
        dedup_key="dk1",
        count=1,
        first_seen=now,
        last_seen=now,
        evidence={},
    )


def _connector(
    org: Organization, ctype: str, *, config: dict, secret: str | None
) -> NotificationConnector:
    return NotificationConnector(
        organization_id=org.id,
        name=f"c-{ctype}",
        type=ctype,
        config=config,
        secret=secret,
        min_severity="high",
        enabled=True,
    )


def test_pagerduty_payload(org: Organization) -> None:
    client, seen = _capture()
    c = _connector(org, "pagerduty", config={}, secret="rk-123")
    assert deliver_one(c, _finding(org), org, http_client=client) is True
    assert seen[0].url.host == "events.pagerduty.com"
    body = json.loads(seen[0].content)
    assert body["routing_key"] == "rk-123"
    assert body["payload"]["severity"] == "critical"


def test_opsgenie_payload(org: Organization) -> None:
    client, seen = _capture()
    c = _connector(org, "opsgenie", config={}, secret="gk-9")
    assert deliver_one(c, _finding(org), org, http_client=client) is True
    assert seen[0].headers["authorization"] == "GenieKey gk-9"
    assert json.loads(seen[0].content)["priority"] == "P1"


def test_jira_payload(org: Organization) -> None:
    client, seen = _capture()
    c = _connector(
        org,
        "jira",
        config={"instance_url": "https://example.com", "email": "a@acme.com", "project": "SEC"},
        secret="token",
    )
    assert deliver_one(c, _finding(org), org, http_client=client) is True
    assert seen[0].url.path == "/rest/api/2/issue"
    assert seen[0].headers["authorization"].startswith("Basic ")
    assert json.loads(seen[0].content)["fields"]["project"]["key"] == "SEC"


def test_servicenow_payload(org: Organization) -> None:
    client, seen = _capture()
    c = _connector(
        org,
        "servicenow",
        config={"instance_url": "https://example.com", "user": "svc"},
        secret="pw",
    )
    assert deliver_one(c, _finding(org), org, http_client=client) is True
    assert seen[0].url.path == "/api/now/table/incident"
    assert json.loads(seen[0].content)["urgency"] == "1"


def test_missing_secret_is_not_delivered(org: Organization) -> None:
    client, seen = _capture()
    c = _connector(org, "pagerduty", config={}, secret=None)
    assert deliver_one(c, _finding(org), org, http_client=client) is False
    assert seen == []
    assert c.last_status == "error"


def test_dispatch_respects_min_severity(
    session: Session, org: Organization
) -> None:
    client, _seen = _capture()
    c = _connector(org, "pagerduty", config={}, secret="rk")
    c.min_severity = "high"
    session.add(c)
    session.commit()
    # A low finding is below the connector's threshold → not delivered.
    assert dispatch_finding(session, _finding(org, "low"), org, http_client=client) == 0
    # A critical finding is delivered.
    assert dispatch_finding(session, _finding(org, "critical"), org, http_client=client) == 1


def test_dispatch_ssrf_guarded_webhook(
    session: Session, org: Organization
) -> None:
    client, seen = _capture()
    c = _connector(org, "webhook", config={"url": "http://169.254.169.254/x"}, secret=None)
    session.add(c)
    session.commit()
    assert dispatch_finding(session, _finding(org), org, http_client=client) == 0
    assert seen == []


# --- CRUD + secrets + RBAC --------------------------------------------------
def test_connector_crud_and_secret_masking(
    monkeypatch, client: TestClient, session: Session, org: Organization
) -> None:
    from cryptography.fernet import Fernet

    from app.services.crypto import reset_cipher

    monkeypatch.setattr(get_settings(), "secret_keys", [Fernet.generate_key().decode()])
    reset_cipher()

    r = client.post(
        "/notifications/connectors",
        json={"name": "pd", "type": "pagerduty", "secret": "rk-secret"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["secret_set"] is True
    assert "rk-secret" not in r.text  # never echoed

    # Stored secret is encrypted at rest, decrypts to the original.
    row = session.query(NotificationConnector).filter_by(organization_id=org.id).one()
    assert row.secret is not None and row.secret.startswith("enc:v1:")
    assert unseal(row.secret) == "rk-secret"

    assert len(client.get("/notifications/connectors").json()) == 1


def test_connectors_require_admin(monkeypatch, app, org: Organization) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["an"])
    monkeypatch.setattr(s, "api_key_orgs", {"an": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"an": "analyst"})
    c = TestClient(app)
    c.headers.update({"X-API-Key": "an", "X-Org-Slug": "acme"})
    assert c.get("/notifications/connectors").status_code == 403
    assert (
        c.post(
            "/notifications/connectors",
            json={"name": "x", "type": "slack"},
        ).status_code
        == 403
    )
