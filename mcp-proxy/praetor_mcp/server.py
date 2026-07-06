"""MCP transport wiring — the runtime adapter around :class:`PolicyGate`.

Bridges a downstream MCP server (what the agent connects to) to one or more
upstream MCP servers (the real tools), routing every ``tools/call`` through the
gate. The optional ``mcp`` package is imported lazily so the policy core and CI
never require the MCP runtime; install it with ``pip install praetor-mcp[runtime]``.

Targets ``mcp>=1.2`` (low-level ``Server`` + ``ClientSession``). This adapter is
validated against real MCP servers in staging, not in unit CI — the tested
surface is ``PolicyGate``/``config``. Structure:

* connect each configured upstream (stdio subprocess or streamable-HTTP);
* ``tools/list`` -> aggregate upstream tools, namespace them ``<server>__<tool>``,
  and drop any the gate hides;
* ``tools/call`` -> split the namespace, gate the call, then forward the
  (possibly transformed) arguments upstream, or return an MCP tool error on deny.
"""

from __future__ import annotations

import uuid
from contextlib import AsyncExitStack
from typing import Any

from praetor_mcp.config import ProxyConfig, UpstreamConfig, build_client
from praetor_mcp.gate import NAMESPACE_SEP, PolicyGate


class ProxyServer:  # pragma: no cover - exercised against a real MCP runtime
    """Aggregating MCP proxy: N upstreams behind one policed endpoint."""

    def __init__(self, config: ProxyConfig) -> None:
        self._config = config
        self._gate = PolicyGate(
            build_client(config), on_error=config.enforcement.on_error
        )
        self._session_id = uuid.uuid4().hex
        self._agent_id = config.agent_id
        # name -> (upstream_name, upstream_tool_name, ClientSession)
        self._routes: dict[str, tuple[str, str, Any]] = {}
        self._stack = AsyncExitStack()

    async def _connect_upstream(self, up: UpstreamConfig) -> Any:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        if up.transport == "stdio":
            params = StdioServerParameters(
                command=up.command[0], args=up.command[1:], env=up.env or None
            )
            read, write = await self._stack.enter_async_context(stdio_client(params))
        else:
            from mcp.client.streamable_http import streamablehttp_client

            assert up.url is not None
            read, write, _ = await self._stack.enter_async_context(
                streamablehttp_client(up.url)
            )
        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        return session

    async def _load_routes(self) -> list[Any]:
        """Connect upstreams and build the namespaced, gate-filtered tool list."""
        from mcp import types

        tools: list[Any] = []
        for up in self._config.upstreams:
            session = await self._connect_upstream(up)
            listed = await session.list_tools()
            for tool in listed.tools:
                if self._config.enforcement.hide_denied_tools and not (
                    self._gate.is_tool_visible(
                        tool.name,
                        session_id=self._session_id,
                        server=up.name,
                        agent_id=self._agent_id,
                    )
                ):
                    continue
                namespaced = f"{up.name}{NAMESPACE_SEP}{tool.name}"
                self._routes[namespaced] = (up.name, tool.name, session)
                tools.append(
                    types.Tool(
                        name=namespaced,
                        description=tool.description,
                        inputSchema=tool.inputSchema,
                    )
                )
        return tools

    def _split(self, namespaced: str) -> tuple[str | None, str]:
        server, _, tool = namespaced.partition(NAMESPACE_SEP)
        return (server, tool) if tool else (None, namespaced)

    async def run(self) -> None:
        from mcp.server.lowlevel import Server

        server: Server = Server("praetor-mcp")
        tools = await self._load_routes()

        @server.list_tools()
        async def _list_tools() -> list[Any]:
            return tools

        @server.call_tool()
        async def _call_tool(name: str, arguments: dict[str, Any]) -> list[Any]:
            server_name, tool = self._split(name)
            gated = self._gate.gate_tool_call(
                tool=tool,
                arguments=arguments or {},
                session_id=self._session_id,
                server=server_name,
                agent_id=self._agent_id,
            )
            if gated.is_error:
                # Surface the block as tool content; low-level Server marks a
                # raised error as isError. Raise so the agent sees the reason.
                raise RuntimeError(gated.error_text())
            route = self._routes.get(name)
            if route is None:
                raise RuntimeError(f"unknown tool {name!r}")
            _up_name, up_tool, session = route
            result = await session.call_tool(up_tool, gated.arguments)
            return list(result.content)

        await self._serve(server)

    async def _serve(self, server: Any) -> None:
        from mcp.server.lowlevel import NotificationOptions
        from mcp.server.models import InitializationOptions

        init = InitializationOptions(
            server_name="praetor-mcp",
            server_version="0.1.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(),
                experimental_capabilities={},
            ),
        )
        if self._config.listen_transport == "stdio":
            from mcp.server.stdio import stdio_server

            async with stdio_server() as (read, write):
                await server.run(read, write, init)
        else:
            raise NotImplementedError(
                "streamable-http listen transport is wired via the ASGI app in "
                "deployment; use stdio for the v1 sidecar entrypoint"
            )

    async def aclose(self) -> None:
        await self._stack.aclose()


async def run_proxy(config: ProxyConfig) -> None:  # pragma: no cover
    proxy = ProxyServer(config)
    try:
        await proxy.run()
    finally:
        await proxy.aclose()


__all__ = ["ProxyServer", "run_proxy"]
