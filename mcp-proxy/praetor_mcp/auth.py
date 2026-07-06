"""Downstream (incoming agent) authentication for the HTTP listen transport.

A pure-ASGI middleware: it authenticates each request against the configured
bearer tokens, rejects unauthenticated calls with 401, and stamps the resolved
:class:`Identity` (agent from the token, session from ``Mcp-Session-Id``) into
the context variable the gate reads. No MCP runtime dependency, so it is
unit-tested directly.

Without configured tokens the middleware is not installed at all (stdio sidecar
/ dev), preserving the single-identity behavior.
"""

from __future__ import annotations

from typing import Any

from praetor_mcp.identity import Identity, set_identity

_ASGIApp = Any


async def _reject(send: Any) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"text/plain"),
                (b"www-authenticate", b'Bearer realm="praetor-mcp"'),
            ],
        }
    )
    await send({"type": "http.response.body", "body": b"unauthorized"})


class BearerAuthMiddleware:
    """Require ``Authorization: Bearer <token>``; map the token to an agent."""

    def __init__(self, app: _ASGIApp, tokens: dict[str, str]) -> None:
        self._app = app
        self._tokens = tokens

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode()
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        agent = self._tokens.get(token)
        if agent is None:
            await _reject(send)
            return
        raw_sid = headers.get(b"mcp-session-id", b"").decode()
        set_identity(
            Identity(session_id=raw_sid or f"agent:{agent}", agent_id=agent)
        )
        try:
            await self._app(scope, receive, send)
        finally:
            set_identity(None)


__all__ = ["BearerAuthMiddleware"]
