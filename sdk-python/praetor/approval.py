"""Approval flow for `require_approval` decisions.

Webhook-based. The SDK posts an approval request to a configured URL
with a Slack-compatible payload (rich enough for Slack, simple enough
for proprietary inboxes), then blocks until either the request is
resolved or the timeout elapses.

Resolution is delivered by the caller invoking
`ApprovalRegistry.resolve(approval_id, approved=True/False)`. In
production, the control plane's webhook receiver makes this call.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
from praetor_engine.types import PolicyInput

from praetor.errors import ApprovalTimeout


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    agent_id: str
    session_id: str
    tool_name: str
    tool_arguments: Mapping[str, Any]
    policy_id: str | None
    reason: str

    def to_slack_payload(self) -> dict[str, Any]:
        return {
            "text": (
                f":lock: Praetor approval required for `{self.tool_name}` "
                f"(agent={self.agent_id}, session={self.session_id})"
            ),
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Approval required*\n"
                            f"*Tool:* `{self.tool_name}`\n"
                            f"*Policy:* `{self.policy_id or '<none>'}`\n"
                            f"*Reason:* {self.reason}\n"
                            f"*Agent:* `{self.agent_id}`\n"
                            f"*Session:* `{self.session_id}`"
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
                            "value": f"approve:{self.id}",
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Deny"},
                            "style": "danger",
                            "value": f"deny:{self.id}",
                        },
                    ],
                },
            ],
            "praetor": {
                "approval_id": self.id,
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "tool_name": self.tool_name,
                "tool_arguments": dict(self.tool_arguments),
                "policy_id": self.policy_id,
            },
        }


@dataclass
class _Pending:
    event: threading.Event = field(default_factory=threading.Event)
    approved: bool | None = None


class ApprovalRegistry:
    """In-memory map of approval-id → pending request. Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}

    def register(self, approval_id: str) -> _Pending:
        with self._lock:
            pending = _Pending()
            self._pending[approval_id] = pending
            return pending

    def resolve(self, approval_id: str, *, approved: bool) -> bool:
        with self._lock:
            pending = self._pending.get(approval_id)
        if pending is None:
            return False
        pending.approved = approved
        pending.event.set()
        return True

    def _discard(self, approval_id: str) -> None:
        with self._lock:
            self._pending.pop(approval_id, None)


class ApprovalHandler(Protocol):
    """Blocking call: returns True if approved, False if denied.

    Raises `ApprovalTimeout` if no decision arrives in time.
    """

    def request_approval(
        self,
        policy_input: PolicyInput,
        *,
        policy_id: str | None,
        reason: str,
    ) -> bool: ...


class WebhookApprovalHandler:
    """Posts a Slack-compatible payload to a webhook, then blocks for the callback."""

    def __init__(
        self,
        webhook_url: str,
        registry: ApprovalRegistry,
        *,
        timeout_seconds: float = 300.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._url = webhook_url
        self._registry = registry
        self._timeout = timeout_seconds
        self._client = http_client or httpx.Client(timeout=10.0)

    def request_approval(
        self,
        policy_input: PolicyInput,
        *,
        policy_id: str | None,
        reason: str,
    ) -> bool:
        approval_id = str(uuid.uuid4())
        request = ApprovalRequest(
            id=approval_id,
            agent_id=policy_input.agent.id,
            session_id=policy_input.session.id,
            tool_name=policy_input.tool.name,
            tool_arguments=policy_input.tool.arguments,
            policy_id=policy_id,
            reason=reason,
        )
        pending = self._registry.register(approval_id)
        try:
            response = self._client.post(self._url, json=request.to_slack_payload())
            response.raise_for_status()
            ok = pending.event.wait(timeout=self._timeout)
            if not ok:
                raise ApprovalTimeout(
                    f"approval {approval_id} not resolved within {self._timeout}s"
                )
            assert pending.approved is not None
            return pending.approved
        finally:
            self._registry._discard(approval_id)


__all__ = [
    "ApprovalHandler",
    "ApprovalRegistry",
    "ApprovalRequest",
    "WebhookApprovalHandler",
]
