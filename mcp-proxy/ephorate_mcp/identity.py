"""Per-request caller identity (agent + session).

In the stdio sidecar one identity covers the process. In the streamable-HTTP
gateway, many agents share one proxy, so identity must be resolved per request
— from the authenticated bearer token (agent) and the ``Mcp-Session-Id`` header
(session). It is carried in a context variable that the auth middleware sets and
the gate reads, so audit attribution, per-agent quarantine, and UEBA baselines
stay correct across concurrent sessions.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    session_id: str
    agent_id: str | None = None


_current: ContextVar[Identity | None] = ContextVar(
    "ephorate_mcp_identity", default=None
)


def set_identity(identity: Identity | None) -> None:
    _current.set(identity)


def current_identity() -> Identity | None:
    """The identity resolved for the in-flight request, or None (stdio path)."""
    return _current.get()


__all__ = ["Identity", "current_identity", "set_identity"]
