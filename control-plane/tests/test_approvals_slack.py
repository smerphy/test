from __future__ import annotations

import hashlib
import hmac
import json
import time
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import ApprovalRequest, ApprovalStatus, Organization

_SECRET = "test-signing-secret"


def _seed(session: Session, org: Organization) -> ApprovalRequest:
    a = ApprovalRequest(
        organization_id=org.id,
        agent_id="agent-1",
        session_id="sess-1",
        tool_name="http.post",
        tool_arguments={"url": "https://x"},
        policy_id="needs-human",
        reason="payment > $10k",
    )
    session.add(a)
    session.commit()
    return a


def _signed_body(value: str, *, ts: int | None = None, secret: str = _SECRET):
    payload = {"user": {"username": "bob"}, "actions": [{"value": value}]}
    body = "payload=" + quote(json.dumps(payload))
    ts = ts if ts is not None else int(time.time())
    base = f"v0:{ts}:{body}".encode()
    sig = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Slack-Signature": sig,
        "X-Slack-Request-Timestamp": str(ts),
    }
    return body, headers


@pytest.fixture
def slack_secret(monkeypatch):
    from app.settings import get_settings

    monkeypatch.setattr(get_settings(), "slack_signing_secret", _SECRET)


def test_slack_approve_resolves(
    client: TestClient, session: Session, org: Organization, slack_secret
) -> None:
    a = _seed(session, org)
    body, headers = _signed_body(f"approve:{a.id}")
    r = client.post("/approvals/slack/actions", content=body, headers=headers)
    assert r.status_code == 200
    assert "approved" in r.json()["text"]
    assert client.get(f"/approvals/{a.id}").json()["status"] == "approved"


def test_slack_deny_resolves(
    client: TestClient, session: Session, org: Organization, slack_secret
) -> None:
    a = _seed(session, org)
    body, headers = _signed_body(f"deny:{a.id}")
    r = client.post("/approvals/slack/actions", content=body, headers=headers)
    assert r.status_code == 200
    assert client.get(f"/approvals/{a.id}").json()["status"] == "denied"


def test_slack_bad_signature_rejected(
    client: TestClient, session: Session, org: Organization, slack_secret
) -> None:
    a = _seed(session, org)
    body, headers = _signed_body(f"approve:{a.id}", secret="wrong-secret")
    r = client.post("/approvals/slack/actions", content=body, headers=headers)
    assert r.status_code == 401


def test_slack_stale_timestamp_rejected(
    client: TestClient, session: Session, org: Organization, slack_secret
) -> None:
    a = _seed(session, org)
    body, headers = _signed_body(f"approve:{a.id}", ts=int(time.time()) - 10_000)
    r = client.post("/approvals/slack/actions", content=body, headers=headers)
    assert r.status_code == 401


def test_slack_endpoint_503_when_secret_unset(
    client: TestClient, session: Session, org: Organization
) -> None:
    # No slack_secret fixture: signing secret is the default empty string.
    a = _seed(session, org)
    body, headers = _signed_body(f"approve:{a.id}")
    r = client.post("/approvals/slack/actions", content=body, headers=headers)
    assert r.status_code == 503


def test_slack_already_resolved_returns_message(
    client: TestClient, session: Session, org: Organization, slack_secret
) -> None:
    a = _seed(session, org)
    a.status = ApprovalStatus.APPROVED
    session.commit()
    body, headers = _signed_body(f"deny:{a.id}")
    r = client.post("/approvals/slack/actions", content=body, headers=headers)
    assert r.status_code == 200
    assert "Already approved" in r.json()["text"]
