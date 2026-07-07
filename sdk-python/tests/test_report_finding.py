"""EphorateClient.report_finding — best-effort finding submission."""

from __future__ import annotations

import json

import httpx

from ephorate.client import EphorateClient


def _capturing_client(captured: list[dict]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(
            {"path": request.url.path, "body": json.loads(request.content)}
        )
        return httpx.Response(200, json={"id": "f1"})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_report_finding_posts_all_fields() -> None:
    captured: list[dict] = []
    client = EphorateClient(policies=[], default_agent_id="research-bot")
    client._control_plane_base = "http://cp"
    client._heartbeat_client = _capturing_client(captured)
    client._heartbeat_headers = {}

    client.report_finding(
        "saw a suspicious redirect",
        category="prompt_injection",
        suggested_severity="high",
        session_id="sess-1",
        evidence={"url": "https://x/1"},
    )

    assert len(captured) == 1
    assert captured[0]["path"] == "/findings/report"
    body = captured[0]["body"]
    assert body["observation"] == "saw a suspicious redirect"
    assert body["agent_id"] == "research-bot"  # falls back to default
    assert body["session_id"] == "sess-1"
    assert body["category"] == "prompt_injection"
    assert body["suggested_severity"] == "high"
    assert body["evidence"] == {"url": "https://x/1"}


def test_report_finding_noop_without_control_plane() -> None:
    client = EphorateClient(policies=[], default_agent_id="a")
    # No control plane wired -> silent no-op, no raise.
    assert client.report_finding("anything") is None


def test_report_finding_swallows_errors() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = EphorateClient(policies=[], default_agent_id="a")
    client._control_plane_base = "http://cp"
    client._heartbeat_client = httpx.Client(transport=httpx.MockTransport(boom))
    client._heartbeat_headers = {}

    # Best-effort: a transport failure must not propagate.
    assert client.report_finding("obs", agent_id="explicit") is None
