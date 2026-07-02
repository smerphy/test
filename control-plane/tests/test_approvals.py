from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import ApprovalRequest, ApprovalStatus, Organization


def _seed_approval(session: Session, org: Organization) -> ApprovalRequest:
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


def test_list_pending(client: TestClient, session: Session, org: Organization) -> None:
    _seed_approval(session, org)
    r = client.get("/approvals")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["status"] == "pending"


def test_resolve_approval_marks_approved(
    client: TestClient, session: Session, org: Organization
) -> None:
    a = _seed_approval(session, org)
    r = client.post(
        f"/approvals/{a.id}/resolve",
        json={"approved": True, "resolved_by": "bob@acme.com"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "approved"
    assert body["resolved_by"] == "bob@acme.com"
    assert body["resolved_at"] is not None


def test_resolve_approval_marks_denied(
    client: TestClient, session: Session, org: Organization
) -> None:
    a = _seed_approval(session, org)
    r = client.post(f"/approvals/{a.id}/resolve", json={"approved": False})
    assert r.json()["status"] == "denied"


def test_cannot_resolve_twice(
    client: TestClient, session: Session, org: Organization
) -> None:
    a = _seed_approval(session, org)
    a.status = ApprovalStatus.APPROVED
    session.commit()
    r = client.post(f"/approvals/{a.id}/resolve", json={"approved": True})
    assert r.status_code == 409


def test_unknown_approval_returns_404(client: TestClient) -> None:
    r = client.post("/approvals/missing/resolve", json={"approved": True})
    assert r.status_code == 404


def test_create_then_poll_lifecycle(client: TestClient) -> None:
    # The SDK path: create a pending approval, poll it, resolve it, poll again.
    created = client.post(
        "/approvals",
        json={
            "agent_id": "agent-1",
            "session_id": "sess-1",
            "tool_name": "http.post",
            "tool_arguments": {"url": "https://x"},
            "policy_id": "needs-human",
            "reason": "payment > $10k",
        },
    )
    assert created.status_code == 201
    approval_id = created.json()["id"]
    assert created.json()["status"] == "pending"

    assert client.get(f"/approvals/{approval_id}").json()["status"] == "pending"

    client.post(f"/approvals/{approval_id}/resolve", json={"approved": True})
    assert client.get(f"/approvals/{approval_id}").json()["status"] == "approved"


def test_get_approval_is_org_scoped(
    client: TestClient, session: Session, org: Organization
) -> None:
    other = Organization(name="Other", slug="other")
    session.add(other)
    session.commit()
    foreign = ApprovalRequest(
        organization_id=other.id,
        agent_id="a",
        session_id="s",
        tool_name="t",
        tool_arguments={},
        policy_id=None,
        reason="r",
    )
    session.add(foreign)
    session.commit()
    # `client` acts as `acme`; the rival org's approval must not be visible.
    assert client.get(f"/approvals/{foreign.id}").status_code == 404
