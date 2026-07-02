"""Outbound notifications for pending approvals.

When a `require_approval` decision creates a pending approval, we post a
Slack-compatible message to the organization's `approval_webhook_url` so a
human is pinged instead of having to watch the dashboard. Delivery is
best-effort: a failure is swallowed (the dashboard inbox remains the
source of truth), never surfaced to the SDK that created the approval.
"""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.models import ApprovalRequest, Organization


def build_approval_payload(approval: ApprovalRequest) -> dict[str, Any]:
    """A Slack-incoming-webhook-compatible payload (also fine for a generic
    JSON webhook — the structured `praetor` block carries the raw fields)."""
    return {
        "text": (
            f":lock: Praetor approval required for `{approval.tool_name}` "
            f"(agent={approval.agent_id})"
        ),
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Approval required*\n"
                        f"*Tool:* `{approval.tool_name}`\n"
                        f"*Policy:* `{approval.policy_id or '<none>'}`\n"
                        f"*Reason:* {approval.reason}\n"
                        f"*Agent:* `{approval.agent_id}`\n"
                        f"*Session:* `{approval.session_id}`\n"
                        f"*Approval ID:* `{approval.id}`"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "value": f"approve:{approval.id}",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "style": "danger",
                        "value": f"deny:{approval.id}",
                    },
                ],
            },
        ],
        "praetor": {
            "approval_id": approval.id,
            "agent_id": approval.agent_id,
            "session_id": approval.session_id,
            "tool_name": approval.tool_name,
            "tool_arguments": approval.tool_arguments,
            "policy_id": approval.policy_id,
            "reason": approval.reason,
        },
    }


def deliver_approval_notification(
    session: Session,
    approval_id: str,
    *,
    http_client: httpx.Client | None = None,
) -> bool:
    """Post the pending-approval notification to the org webhook.

    Returns True on delivery, False if there is nothing to deliver (unknown
    approval, no configured webhook) or delivery failed. Never raises.
    """
    approval = session.get(ApprovalRequest, approval_id)
    if approval is None:
        return False
    org = session.get(Organization, approval.organization_id)
    if org is None or not org.approval_webhook_url:
        return False
    client = http_client or httpx.Client(timeout=10.0)
    try:
        r = client.post(
            org.approval_webhook_url, json=build_approval_payload(approval)
        )
        r.raise_for_status()
        return True
    except Exception:
        return False


__all__ = ["build_approval_payload", "deliver_approval_notification"]
