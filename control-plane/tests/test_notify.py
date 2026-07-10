from __future__ import annotations

import httpx
from sqlalchemy.orm import Session

from app.models import ApprovalRequest, Organization
from app.services.notify import (
    build_approval_payload,
    deliver_approval_notification,
)


def _approval(session: Session, org: Organization) -> ApprovalRequest:
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


def _client(handler: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


def test_payload_carries_raw_fields(session: Session, org: Organization) -> None:
    a = _approval(session, org)
    payload = build_approval_payload(a)
    assert payload["ephorate"]["approval_id"] == a.id
    assert payload["ephorate"]["tool_name"] == "http.post"
    assert "Approval required" in payload["blocks"][0]["text"]["text"]


def test_delivers_when_webhook_configured(
    session: Session, org: Organization
) -> None:
    org.approval_webhook_url = "https://example.com/hook"
    a = _approval(session, org)
    posted: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        posted.append(json.loads(request.content))
        return httpx.Response(200)

    ok = deliver_approval_notification(session, a.id, http_client=_client(handler))
    assert ok is True
    assert posted[0]["ephorate"]["approval_id"] == a.id


def test_noop_when_no_webhook(session: Session, org: Organization) -> None:
    a = _approval(session, org)  # org has no webhook by default
    assert deliver_approval_notification(session, a.id) is False


def test_delivery_failure_is_swallowed(
    session: Session, org: Organization
) -> None:
    org.approval_webhook_url = "https://example.com/hook"
    a = _approval(session, org)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    # Must not raise; a failed notification never blocks the approval flow.
    assert deliver_approval_notification(
        session, a.id, http_client=_client(handler)
    ) is False
