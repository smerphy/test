"""High-level SDK client wrapping the engine + audit + approval flow."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from praetor_engine.evaluator import Evaluator, Policy
from praetor_engine.parser import parse_bundle_file
from praetor_engine.types import (
    AgentInfo,
    Decision,
    DecisionResult,
    PolicyInput,
    SessionInfo,
    ToolCall,
)

from praetor.approval import ApprovalHandler
from praetor.audit import AuditSink, NullAuditSink
from praetor.errors import PolicyDenied


class PraetorClient:
    """Evaluates tool calls against policy, records audit, runs approval flow.

    Configurable:
      - `policies` or `bundle_path` — the policy bundle to evaluate against
      - `audit_sink` — durable audit recorder (default: NullAuditSink)
      - `approval_handler` — blocking handler for REQUIRE_APPROVAL (default: none,
        unhandled approvals become DENY)
      - `default_agent_id` — used when caller does not pass one per call
    """

    def __init__(
        self,
        *,
        policies: Sequence[Policy] | None = None,
        bundle_path: Path | None = None,
        audit_sink: AuditSink | None = None,
        approval_handler: ApprovalHandler | None = None,
        default_agent_id: str | None = None,
    ) -> None:
        if policies is not None and bundle_path is not None:
            raise ValueError("pass policies or bundle_path, not both")
        if bundle_path is not None:
            policies = parse_bundle_file(bundle_path)
        self._evaluator = Evaluator(policies=policies or [])
        self._audit: AuditSink = audit_sink or NullAuditSink()
        self._approval = approval_handler
        self._default_agent_id = default_agent_id

    @property
    def policies(self) -> tuple[Policy, ...]:
        return self._evaluator.policies

    def evaluate(
        self,
        tool_name: str,
        tool_arguments: Mapping[str, Any],
        *,
        session_id: str,
        agent_id: str | None = None,
        agent_name: str | None = None,
        agent_version: str | None = None,
        tool_use_id: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> DecisionResult:
        """Evaluate a tool call and run the approval flow if required.

        Returns the final `DecisionResult`. Records exactly one audit
        event per call, even when approval is solicited.
        """
        resolved_agent_id = agent_id or self._default_agent_id
        if not resolved_agent_id:
            raise ValueError(
                "agent_id must be passed or `default_agent_id` set on the client"
            )

        policy_input = PolicyInput(
            agent=AgentInfo(
                id=resolved_agent_id, name=agent_name, version=agent_version
            ),
            tool=ToolCall(
                name=tool_name,
                arguments=dict(tool_arguments),
                tool_use_id=tool_use_id,
            ),
            session=SessionInfo(id=session_id),
            context=dict(context or {}),
        )

        result = self._evaluator.evaluate(policy_input)

        if result.decision is Decision.REQUIRE_APPROVAL:
            result = self._resolve_approval(policy_input, result)

        self._audit.record(policy_input, result)
        return result

    def enforce(
        self,
        tool_name: str,
        tool_arguments: Mapping[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Evaluate and either return the (possibly transformed) arguments or raise.

        Convenience for callers that just want "let me run this, throw if not".
        """
        result = self.evaluate(tool_name, tool_arguments, **kwargs)
        if result.decision is Decision.ALLOW:
            return dict(tool_arguments)
        if result.decision is Decision.TRANSFORM:
            assert result.suggested_transform is not None
            return {**dict(tool_arguments), **result.suggested_transform}
        raise PolicyDenied(result)

    def _resolve_approval(
        self, policy_input: PolicyInput, pending: DecisionResult
    ) -> DecisionResult:
        if self._approval is None:
            return DecisionResult(
                decision=Decision.DENY,
                reason=(
                    f"require_approval requested by {pending.matched_policy_id} "
                    "but no approval handler is configured"
                ),
                matched_policy_id=pending.matched_policy_id,
            )
        approved = self._approval.request_approval(
            policy_input,
            policy_id=pending.matched_policy_id,
            reason=pending.reason,
        )
        if approved:
            return DecisionResult(
                decision=Decision.ALLOW,
                reason=f"approved via {pending.matched_policy_id}",
                matched_policy_id=pending.matched_policy_id,
            )
        return DecisionResult(
            decision=Decision.DENY,
            reason=f"approval denied for {pending.matched_policy_id}",
            matched_policy_id=pending.matched_policy_id,
        )


__all__ = ["PraetorClient"]
