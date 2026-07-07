from __future__ import annotations

import httpx

from ephorate.client import EphorateClient


def _capturing_client(captured: list[dict]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured.append(
            {"path": request.url.path, "body": json.loads(request.content)}
        )
        return httpx.Response(200, json={"agent_id": "x", "health": "active"})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_heartbeat_posts_agent_info() -> None:
    captured: list[dict] = []
    client = EphorateClient(policies=[], default_agent_id="research-bot")
    # No control plane wired; inject heartbeat plumbing directly.
    client._heartbeat_url = "http://cp/agents/heartbeat"
    client._heartbeat_client = _capturing_client(captured)

    client.heartbeat(name="Research Bot", agent_version="2.1")
    assert len(captured) == 1
    assert captured[0]["path"] == "/agents/heartbeat"
    assert captured[0]["body"]["agent_id"] == "research-bot"
    assert captured[0]["body"]["name"] == "Research Bot"
    assert captured[0]["body"]["sdk_version"]  # engine version filled in


def test_heartbeat_is_noop_without_control_plane() -> None:
    client = EphorateClient(policies=[], default_agent_id="a")
    assert client.heartbeat() is None  # no url configured -> silent no-op


def test_heartbeat_swallows_errors() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = EphorateClient(policies=[], default_agent_id="a")
    client._heartbeat_url = "http://cp/agents/heartbeat"
    client._heartbeat_client = httpx.Client(transport=httpx.MockTransport(boom))
    # Must not raise.
    assert client.heartbeat() is None
