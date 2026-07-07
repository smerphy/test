"""End-to-end transport test: proxy ↔ in-memory upstream MCP server.

Exercises the real MCP ClientSession + a mock upstream Server through the
proxy's routing/gate logic (add_upstream / handle_list_tools /
handle_call_tool) — no subprocess or network.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("mcp")

from ephorate import EphorateClient
from ephorate_engine.evaluator import Policy
from ephorate_engine.predicates import EqPredicate
from ephorate_engine.types import Decision
from mcp import types
from mcp.server.lowlevel import Server
from mcp.shared.memory import (
    create_connected_server_and_client_session,
)

from ephorate_mcp.config import parse_config
from ephorate_mcp.gate import PolicyGate
from ephorate_mcp.server import PolicyBlocked, ProxyServer


def _mock_upstream() -> Server:
    up: Server = Server("mock-upstream")

    @up.list_tools()  # type: ignore[no-untyped-call, misc]
    async def _list() -> list[Any]:
        return [
            types.Tool(name="echo", description="echo", inputSchema={"type": "object"}),
            types.Tool(
                name="delete_file", description="danger", inputSchema={"type": "object"}
            ),
        ]

    @up.call_tool()  # type: ignore[no-untyped-call, misc]
    async def _call(name: str, arguments: dict[str, Any]) -> list[Any]:
        return [types.TextContent(type="text", text=f"{name}:{sorted(arguments.items())}")]

    return up


def _config() -> Any:
    return parse_config(
        {
            "agent": {"id": "a"},
            "upstreams": [{"name": "mock", "transport": "stdio", "command": ["x"]}],
            "listen": {"transport": "stdio"},
        }
    )


def _gate(policies: list[Policy]) -> PolicyGate:
    return PolicyGate(EphorateClient(policies=policies, default_agent_id="a"))


def _allow(name: str) -> Policy:
    return Policy(
        id=f"allow-{name}", effect=Decision.ALLOW,
        when=EqPredicate(path="tool.name", value=name), reason="allowed",
    )


async def test_proxy_forwards_allow_hides_and_blocks_deny() -> None:
    policies = [
        _allow("mock__echo"),
        Policy(
            id="deny-del", effect=Decision.DENY,
            when=EqPredicate(path="tool.name", value="mock__delete_file"),
            reason="destructive blocked",
        ),
    ]
    proxy = ProxyServer(_config(), gate=_gate(policies))
    async with create_connected_server_and_client_session(_mock_upstream()) as session:
        await proxy.add_upstream("mock", session)

        # tools/list: echo visible, deny'd delete_file hidden.
        names = [t.name for t in await proxy.handle_list_tools()]
        assert "mock__echo" in names
        assert "mock__delete_file" not in names

        # allow → forwarded to the upstream (which echoes back).
        content = await proxy.handle_call_tool("mock__echo", {"x": 1})
        assert content[0].text.startswith("echo:")
        assert "'x', 1" in content[0].text

        # deny → PolicyBlocked with the policy reason (surfaces as isError).
        with pytest.raises(PolicyBlocked, match="destructive blocked"):
            await proxy.handle_call_tool("mock__delete_file", {})


async def test_proxy_transforms_arguments_before_upstream() -> None:
    policies = [
        Policy(
            id="redact", effect=Decision.TRANSFORM,
            when=EqPredicate(path="tool.name", value="mock__echo"),
            reason="redact secret", transform={"secret": "<redacted>"},
        )
    ]
    proxy = ProxyServer(_config(), gate=_gate(policies))
    async with create_connected_server_and_client_session(_mock_upstream()) as session:
        await proxy.add_upstream("mock", session)
        content = await proxy.handle_call_tool(
            "mock__echo", {"secret": "topsecret", "keep": 1}
        )
        # The upstream received the rewritten arguments, not the original.
        assert "<redacted>" in content[0].text
        assert "topsecret" not in content[0].text


async def test_allowed_but_unrouted_tool_is_blocked() -> None:
    # Policy allows a tool that was never registered upstream.
    proxy = ProxyServer(_config(), gate=_gate([_allow("mock__ghost")]))
    with pytest.raises(PolicyBlocked, match="unknown tool"):
        await proxy.handle_call_tool("mock__ghost", {})


async def test_default_deny_blocks_unknown_tool() -> None:
    proxy = ProxyServer(_config(), gate=_gate([]))  # no policies → default deny
    with pytest.raises(PolicyBlocked):
        await proxy.handle_call_tool("mock__whatever", {})
