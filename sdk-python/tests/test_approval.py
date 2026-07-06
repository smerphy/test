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
    ControlPlaneApprovalHandler,
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


def _cp_client(handler: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


class TestControlPlaneApprovalHandler:
    def test_approved_after_polling(self) -> None:
        state = {"gets": 0, "status": "pending"}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                assert request.url.path == "/approvals"
                return httpx.Response(201, json={"id": "appr-1", "status": "pending"})
            state["gets"] = int(state["gets"]) + 1
            if int(state["gets"]) >= 2:
                state["status"] = "approved"
            return httpx.Response(200, json={"status": state["status"]})

        h = ControlPlaneApprovalHandler(
            "http://cp",
            http_client=_cp_client(handler),
            poll_interval_seconds=0.0,
            sleep=lambda _s: None,
        )
        assert h.request_approval(_pi(), policy_id="p1", reason="r") is True
        assert int(state["gets"]) >= 2  # actually polled

    def test_denied(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(201, json={"id": "x", "status": "pending"})
            return httpx.Response(200, json={"status": "denied"})

        h = ControlPlaneApprovalHandler(
            "http://cp", http_client=_cp_client(handler), sleep=lambda _s: None
        )
        assert h.request_approval(_pi(), policy_id=None, reason="r") is False

    def test_timeout_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(201, json={"id": "x", "status": "pending"})
            return httpx.Response(200, json={"status": "pending"})

        clock = {"t": 0.0}

        h = ControlPlaneApprovalHandler(
            "http://cp",
            http_client=_cp_client(handler),
            timeout_seconds=10.0,
            poll_interval_seconds=1.0,
            monotonic=lambda: clock["t"],
            sleep=lambda _s: clock.__setitem__("t", clock["t"] + 100),
        )
        with pytest.raises(ApprovalTimeout):
            h.request_approval(_pi(), policy_id=None, reason="r")
