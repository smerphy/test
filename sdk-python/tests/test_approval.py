from __future__ import annotations

import threading
import time

import httpx
import pytest
import respx
from praetor_engine.types import AgentInfo, PolicyInput, SessionInfo, ToolCall

from praetor.approval import (
    ApprovalRegistry,
    ApprovalRequest,
    WebhookApprovalHandler,
)
from praetor.errors import ApprovalTimeout


def _pi() -> PolicyInput:
    return PolicyInput(
        agent=AgentInfo(id="agent-1"),
        tool=ToolCall(name="http.post", arguments={"url": "https://x"}),
        session=SessionInfo(id="s1"),
    )


class TestApprovalRequest:
    def test_slack_payload_has_buttons_and_metadata(self) -> None:
        req = ApprovalRequest(
            id="abc",
            agent_id="agent-1",
            session_id="s1",
            tool_name="http.post",
            tool_arguments={"url": "https://x"},
            policy_id="p1",
            reason="needs human",
        )
        payload = req.to_slack_payload()
        assert payload["praetor"]["approval_id"] == "abc"
        # First non-section block contains the buttons.
        action_block = next(b for b in payload["blocks"] if b["type"] == "actions")
        button_values = {el["value"] for el in action_block["elements"]}
        assert button_values == {"approve:abc", "deny:abc"}


class TestApprovalRegistry:
    def test_resolve_unknown_id_returns_false(self) -> None:
        reg = ApprovalRegistry()
        assert reg.resolve("unknown", approved=True) is False

    def test_resolve_known_id(self) -> None:
        reg = ApprovalRegistry()
        pending = reg.register("a1")
        assert reg.resolve("a1", approved=True) is True
        assert pending.approved is True
        assert pending.event.is_set()


@respx.mock
def test_webhook_handler_approves(monkeypatch: pytest.MonkeyPatch) -> None:
    respx.post("https://hooks.example/x").mock(return_value=httpx.Response(200))
    reg = ApprovalRegistry()
    handler = WebhookApprovalHandler(
        "https://hooks.example/x", reg, timeout_seconds=5.0
    )

    # Resolve from a worker after the handler starts blocking.
    def approver() -> None:
        time.sleep(0.05)
        # The handler generates the approval_id internally; grab it from the registry.
        # Wait for any registration.
        deadline = time.time() + 2.0
        while time.time() < deadline:
            with reg._lock:
                ids = list(reg._pending)
            if ids:
                reg.resolve(ids[0], approved=True)
                return
            time.sleep(0.01)

    t = threading.Thread(target=approver)
    t.start()
    assert handler.request_approval(_pi(), policy_id="p1", reason="r") is True
    t.join(timeout=2.0)


@respx.mock
def test_webhook_handler_times_out() -> None:
    respx.post("https://hooks.example/x").mock(return_value=httpx.Response(200))
    handler = WebhookApprovalHandler(
        "https://hooks.example/x",
        ApprovalRegistry(),
        timeout_seconds=0.1,
    )
    with pytest.raises(ApprovalTimeout):
        handler.request_approval(_pi(), policy_id="p1", reason="r")


@respx.mock
def test_webhook_failure_raises() -> None:
    respx.post("https://hooks.example/x").mock(return_value=httpx.Response(500))
    handler = WebhookApprovalHandler(
        "https://hooks.example/x",
        ApprovalRegistry(),
        timeout_seconds=5.0,
    )
    with pytest.raises(httpx.HTTPStatusError):
        handler.request_approval(_pi(), policy_id="p1", reason="r")
