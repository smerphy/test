"""Policy gate: map an MCP tool call to a Praetor decision.

The protocol-agnostic core of the proxy. ``PolicyGate`` wraps a
:class:`praetor.PraetorClient` (engine + audit chain + approval flow +
quarantine kill-switch) and turns one MCP ``tools/call`` into a
:class:`GateResult` the transport layer renders back to the agent:

* allow      -> forward unchanged
* transform  -> forward with rewritten arguments
* deny       -> return an MCP tool error (``isError``) with the reason
* approval   -> resolved inside ``PraetorClient.evaluate``; an unresolved
               require_approval is treated as a deny

Because it drives ``PraetorClient.evaluate``, every gated call is recorded on
the tamper-evident audit chain and a quarantined agent/session is blocked —
with no SDK changes in the agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from praetor import PraetorClient
from praetor_engine.evaluator import Evaluator
from praetor_engine.types import (
    AgentInfo,
    Decision,
    PolicyInput,
    SessionInfo,
    ToolCall,
)

# Separator for gateway-mode namespaced tools: "<server>__<tool>".
NAMESPACE_SEP = "__"


@dataclass
class GateResult:
    """The gate's verdict for one tool call."""

    decision: str
    allow: bool
    arguments: dict[str, Any]
    reason: str
    policy_id: str | None = None
    server: str | None = None
    tool: str = ""

    @property
    def is_error(self) -> bool:
        return not self.allow

    def error_text(self) -> str:
        """Human-facing block message surfaced to the agent as tool content."""
        suffix = f" ({self.policy_id})" if self.policy_id else ""
        return f"Blocked by Praetor policy{suffix}: {self.reason}"


class PolicyGate:
    def __init__(
        self,
        client: PraetorClient,
        *,
        on_error: str = "deny",
        namespace_sep: str = NAMESPACE_SEP,
    ) -> None:
        if on_error not in ("deny", "allow"):
            raise ValueError("on_error must be 'deny' or 'allow'")
        self._client = client
        self._on_error = on_error
        self._sep = namespace_sep
        # A non-recording evaluator over the same policies for tool-list
        # filtering, so listing tools doesn't spam the audit chain.
        self._preview = Evaluator(policies=list(client.policies))

    def _full_name(self, server: str | None, tool: str) -> str:
        return f"{server}{self._sep}{tool}" if server else tool

    def gate_tool_call(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        session_id: str,
        server: str | None = None,
        agent_id: str | None = None,
    ) -> GateResult:
        """Evaluate + audit one tool call. Never raises: an evaluation error
        maps to the configured fail-open/closed decision."""
        full = self._full_name(server, tool)
        try:
            result = self._client.evaluate(
                full,
                arguments,
                session_id=session_id,
                agent_id=agent_id,
                context={"mcp_server": server or "", "source": "mcp-proxy"},
            )
        except Exception as exc:  # evaluator / approval / quarantine failure
            if self._on_error == "allow":
                return GateResult(
                    "allow", True, dict(arguments),
                    f"policy error (fail-open): {exc}", None, server, tool,
                )
            return GateResult(
                "deny", False, dict(arguments),
                f"policy evaluation error (fail-closed): {exc}", None, server, tool,
            )

        decision = result.decision
        if decision is Decision.ALLOW:
            return GateResult(
                "allow", True, dict(arguments), result.reason,
                result.matched_policy_id, server, tool,
            )
        if decision is Decision.TRANSFORM:
            merged = {**dict(arguments), **(result.suggested_transform or {})}
            return GateResult(
                "transform", True, merged, result.reason,
                result.matched_policy_id, server, tool,
            )
        # DENY, or an unresolved REQUIRE_APPROVAL (no handler / timed out).
        return GateResult(
            decision.value, False, dict(arguments), result.reason,
            result.matched_policy_id, server, tool,
        )

    def is_tool_visible(
        self,
        tool: str,
        *,
        session_id: str,
        server: str | None = None,
        agent_id: str | None = None,
    ) -> bool:
        """Whether a tool should appear in ``tools/list``. Hidden only when the
        policy denies it outright (empty-argument preview) — argument-dependent
        policies still surface the tool and enforce at call time. Non-auditing."""
        pi = PolicyInput(
            agent=AgentInfo(id=agent_id or "unknown"),
            tool=ToolCall(name=self._full_name(server, tool), arguments={}),
            session=SessionInfo(id=session_id),
        )
        return self._preview.evaluate(pi).decision is not Decision.DENY


__all__ = ["NAMESPACE_SEP", "GateResult", "PolicyGate"]
