"""MCP transport wiring — the runtime adapter around :class:`PolicyGate`.

Bridges a downstream MCP server (what the agent connects to) to one or more
upstream MCP servers (the real tools), routing every ``tools/call`` through the
gate. The optional ``mcp`` package is imported lazily so the policy core never
requires the MCP runtime at import time; install it with
``pip install praetor-mcp[runtime]``.

Targets ``mcp>=1.2`` (low-level ``Server`` + ``ClientSession``). The routing +
gate logic (``add_upstream`` / ``handle_list_tools`` / ``handle_call_tool``) is
transport-agnostic and unit-tested against an in-memory upstream; the parts
that open real transports (``_connect_upstream`` / ``run`` / ``_serve``) are
validated in staging.

* connect each configured upstream (stdio subprocess or streamable-HTTP);
* ``tools/list`` -> aggregate upstream tools, namespace them ``<server>__<tool>``,
  and drop any the gate hides;
* ``tools/call`` -> split the namespace, gate the call, then forward the
  (possibly transformed) arguments upstream, or raise so the agent sees an MCP
  tool error (``isError``) with the reason.
"""

from __future__ import annotations

import uuid
from contextlib import AsyncExitStack
from typing import Any

from praetor_mcp.config import ProxyConfig, UpstreamConfig, build_client
from praetor_mcp.gate import NAMESPACE_SEP, PolicyGate
from praetor_mcp.identity import Identity, current_identity


class PolicyBlocked(RuntimeError):
    """Raised from the call handler when policy denies a tool call. The MCP
    framework surfaces a raised error to the agent as an ``isError`` result."""


class ProxyServer:
    """Aggregating MCP proxy: N upstreams behind one policed endpoint."""

    def __init__(self, config: ProxyConfig, *, gate: PolicyGate | None = None) -> None:
        self._config = config
        self._gate = gate or PolicyGate(
            build_client(config), on_error=config.enforcement.on_error
        )
        # Fallback identity for the stdio sidecar (one agent per process). In
        # HTTP mode the auth middleware sets a per-request identity that
        # _identity() prefers.
        self._default_identity = Identity(
            session_id=uuid.uuid4().hex, agent_id=config.agent_id
        )
        # namespaced name -> (upstream_name, upstream_tool_name, ClientSession)
        self._routes: dict[str, tuple[str, str, Any]] = {}
        self._tools: list[Any] = []
        self._stack = AsyncExitStack()

    # --- transport-agnostic routing (unit-tested) ---------------------------
    def _identity(self) -> Identity:
        """The caller identity for the in-flight request: the per-request one
        set by the auth middleware, else the process default."""
        return current_identity() or self._default_identity

    def _split(self, namespaced: str) -> tuple[str | None, str]:
        server, _, tool = namespaced.partition(NAMESPACE_SEP)
        return (server, tool) if tool else (None, namespaced)

    async def add_upstream(self, name: str, session: Any) -> None:
        """List an already-connected upstream's tools, namespace + gate-filter
        them, and register routes."""
        from mcp import types

        idn = self._identity()
        listed = await session.list_tools()
        for tool in listed.tools:
            if self._config.enforcement.hide_denied_tools and not (
                self._gate.is_tool_visible(
                    tool.name,
                    session_id=idn.session_id,
                    server=name,
                    agent_id=idn.agent_id,
                )
            ):
                continue
            namespaced = f"{name}{NAMESPACE_SEP}{tool.name}"
            self._routes[namespaced] = (name, tool.name, session)
            self._tools.append(
                types.Tool(
                    name=namespaced,
                    description=tool.description,
                    inputSchema=tool.inputSchema,
                )
            )

    async def handle_list_tools(self) -> list[Any]:
        return self._tools

    async def handle_call_tool(self, name: str, arguments: dict[str, Any]) -> list[Any]:
        server_name, tool = self._split(name)
        idn = self._identity()
        gated = self._gate.gate_tool_call(
            tool=tool,
            arguments=arguments or {},
            session_id=idn.session_id,
            server=server_name,
            agent_id=idn.agent_id,
        )
        if gated.is_error:
            raise PolicyBlocked(gated.error_text())
        route = self._routes.get(name)
        if route is None:
            raise PolicyBlocked(f"unknown tool {name!r}")
        _up_name, up_tool, session = route
        result = await session.call_tool(up_tool, gated.arguments)
        return list(result.content)

    # --- real transports (staging-validated) --------------------------------
    async def _connect_upstream(self, up: UpstreamConfig) -> Any:  # pragma: no cover
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

    async def _load_routes(self) -> None:  # pragma: no cover
        for up in self._config.upstreams:
            session = await self._connect_upstream(up)
            await self.add_upstream(up.name, session)

    def build_server(self) -> Any:
        """Build a low-level MCP Server whose handlers delegate to this proxy.
        Shared by the stdio and streamable-HTTP listen transports."""
        from mcp.server.lowlevel import Server

        server: Server = Server("praetor-mcp")

        @server.list_tools()
        async def _list_tools() -> list[Any]:
            return await self.handle_list_tools()

        @server.call_tool()
        async def _call_tool(name: str, arguments: dict[str, Any]) -> list[Any]:
            return await self.handle_call_tool(name, arguments or {})

        return server

    async def run(self) -> None:  # pragma: no cover
        await self._load_routes()
        await self._serve(self.build_server())

    async def _serve(self, server: Any) -> None:  # pragma: no cover
        """Serve over stdio (the sidecar listen transport). Streamable-HTTP is
        served via the ASGI app instead — see build_asgi_app / run_http."""
        from mcp.server.lowlevel import NotificationOptions
        from mcp.server.models import InitializationOptions
        from mcp.server.stdio import stdio_server

        init = InitializationOptions(
            server_name="praetor-mcp",
            server_version="0.1.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(),
                experimental_capabilities={},
            ),
        )
        async with stdio_server() as (read, write):
            await server.run(read, write, init)

    async def aclose(self) -> None:
        """Close upstream connections and flush/stop the audit shipper so a
        clean shutdown never drops locally-buffered events."""
        await self._stack.aclose()
        self._gate.close()


async def run_proxy(config: ProxyConfig) -> None:  # pragma: no cover
    """Run the stdio sidecar listen transport."""
    proxy = ProxyServer(config)
    try:
        await proxy.run()
    finally:
        await proxy.aclose()


def build_asgi_app(config: ProxyConfig) -> Any:
    """Build the Streamable-HTTP ASGI app (deployment mode).

    A Starlette app mounts the MCP session manager at ``config.listen_path``;
    its lifespan connects the upstreams and runs the session manager. Serve it
    with any ASGI server (see :func:`run_http`), or mount it in a larger app.
    """
    from contextlib import asynccontextmanager

    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Mount, Route

    from praetor_mcp.auth import BearerAuthMiddleware

    proxy = ProxyServer(config)
    manager = StreamableHTTPSessionManager(app=proxy.build_server())

    # The MCP endpoint, optionally behind bearer auth that also stamps the
    # per-request identity (agent from the token, session from the header).
    mcp_app: Any = manager.handle_request
    if config.listen_auth_tokens:
        mcp_app = BearerAuthMiddleware(mcp_app, config.listen_auth_tokens)

    async def _health(_req: Any) -> Any:
        return PlainTextResponse("ok")

    async def _ready(_req: Any) -> Any:
        # Ready once at least one upstream tool is routed (upstreams connected).
        code = 200 if proxy._routes else 503
        return PlainTextResponse("ready" if code == 200 else "starting", status_code=code)

    @asynccontextmanager
    async def lifespan(_app: Any) -> Any:  # pragma: no cover - needs a running server
        await proxy._load_routes()
        async with manager.run():
            try:
                yield
            finally:
                await proxy.aclose()

    return Starlette(
        routes=[
            Route("/healthz", _health),
            Route("/readyz", _ready),
            Mount(config.listen_path, app=mcp_app),
        ],
        lifespan=lifespan,
    )


def run_http(config: ProxyConfig) -> None:  # pragma: no cover - binds a port
    """Serve the Streamable-HTTP ASGI app with uvicorn on ``listen_bind``."""
    import uvicorn

    host, _, port = (config.listen_bind or "127.0.0.1:8090").partition(":")
    uvicorn.run(build_asgi_app(config), host=host or "127.0.0.1", port=int(port or 8090))


__all__ = [
    "PolicyBlocked",
    "ProxyServer",
    "build_asgi_app",
    "run_http",
    "run_proxy",
]
