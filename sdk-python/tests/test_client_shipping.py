"""EphorateClient + RemoteShipper wiring + HttpTransport.

Covers the convenience path where a caller passes `control_plane_url`
and `audit_log_path` to EphorateClient and expects events to ship
automatically.
"""

from __future__ import annotations

import time
from pathlib import Path

import httpx
import pytest
import respx
from ephorate_engine.evaluator import Policy
from ephorate_engine.predicates import EqPredicate
from ephorate_engine.types import Decision

from ephorate import EphorateClient, HttpTransport, JsonlAuditSink


def _allow_policy() -> Policy:
    return Policy(
        id="allow-http",
        effect=Decision.ALLOW,
        when=EqPredicate(path="tool.name", value="http.get"),
        reason="ok",
    )


@respx.mock
def test_client_constructs_shipper_when_control_plane_url_provided(
    tmp_path: Path,
) -> None:
    route = respx.post("https://cp.example/audit/events").mock(
        return_value=httpx.Response(202, json={"accepted": 1, "rejected": 0, "errors": []})
    )

    c = EphorateClient(
        policies=[_allow_policy()],
        audit_log_path=tmp_path / "audit.jsonl",
        control_plane_url="https://cp.example",
        api_key="k-test",
        org_slug="acme",
        default_agent_id="agent-1",
    )

    try:
        c.evaluate("http.get", {"url": "https://x"}, session_id="s1")

        # Wait for the background shipper to ack at least one event.
        deadline = time.time() + 2.0
        while time.time() < deadline and route.call_count == 0:
            time.sleep(0.01)

        assert route.call_count >= 1
        # API key + org slug propagated to the transport headers.
        first_request = route.calls[0].request
        assert first_request.headers.get("X-API-Key") == "k-test"
        assert first_request.headers.get("X-Org-Slug") == "acme"
    finally:
        c.stop()


def test_control_plane_url_requires_audit_log_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="control_plane_url requires audit_log_path"):
        EphorateClient(
            policies=[_allow_policy()],
            control_plane_url="https://cp.example",
            default_agent_id="agent-1",
        )


def test_audit_sink_and_audit_log_path_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="audit_sink or audit_log_path"):
        EphorateClient(
            policies=[_allow_policy()],
            audit_sink=JsonlAuditSink(tmp_path / "a.jsonl"),
            audit_log_path=tmp_path / "b.jsonl",
            default_agent_id="agent-1",
        )


@respx.mock
def test_http_transport_raises_on_server_rejection(tmp_path: Path) -> None:
    respx.post("https://cp.example/audit/events").mock(
        return_value=httpx.Response(
            202, json={"accepted": 0, "rejected": 1, "errors": ["prev_hash mismatch"]}
        )
    )

    # Build an event by hand to exercise the transport directly.
    sink = JsonlAuditSink(tmp_path / "audit.jsonl")
    from ephorate_engine.types import (
        AgentInfo,
        DecisionResult,
        PolicyInput,
        SessionInfo,
        ToolCall,
    )

    pi = PolicyInput(
        agent=AgentInfo(id="a"),
        tool=ToolCall(name="t"),
        session=SessionInfo(id="s"),
    )
    decision = DecisionResult(decision=Decision.ALLOW, reason="ok", matched_policy_id="p1")
    event = sink.record(pi, decision)

    transport = HttpTransport("https://cp.example", api_key="k", org_slug="o")
    with pytest.raises(RuntimeError, match="prev_hash mismatch"):
        transport.ship(event)
