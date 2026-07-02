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

from praetor.approval import ApprovalHandler, ControlPlaneApprovalHandler
from praetor.audit import AuditSink, JsonlAuditSink, NullAuditSink, RemoteShipper
from praetor.errors import PolicyDenied
from praetor.transport import HttpTransport


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
        bundle_path: Path | str | None = None,
        audit_sink: AuditSink | None = None,
        audit_log_path: Path | str | None = None,
        control_plane_url: str | None = None,
        api_key: str | None = None,
        org_slug: str | None = None,
        approval_handler: ApprovalHandler | None = None,
        default_agent_id: str | None = None,
    ) -> None:
        if policies is not None and bundle_path is not None:
            raise ValueError("pass policies or bundle_path, not both")
        if bundle_path is not None:
            policies = parse_bundle_file(bundle_path)
        self._evaluator = Evaluator(policies=policies or [])

        # Audit sink resolution:
        #   audit_sink= overrides everything else
        #   audit_log_path= → JsonlAuditSink at that path
        #   neither → NullAuditSink (events dropped silently)
        if audit_sink is not None and audit_log_path is not None:
            raise ValueError("pass audit_sink or audit_log_path, not both")
        if audit_sink is not None:
            self._audit = audit_sink
        elif audit_log_path is not None:
            self._audit = JsonlAuditSink(audit_log_path)
        else:
            self._audit = NullAuditSink()

        self._default_agent_id = default_agent_id

        # Approval handler resolution: an explicit handler wins; otherwise, if
        # a control plane is configured, default to brokering approvals through
        # it (create + poll) so `require_approval` actually resolves. With no
        # handler and no control plane, `require_approval` falls back to deny.
        self._approval = approval_handler
        if self._approval is None and control_plane_url is not None:
            self._approval = ControlPlaneApprovalHandler(
                control_plane_url, api_key=api_key, org_slug=org_slug
            )

        # Optional control-plane shipping. Requires a local JsonlAuditSink
        # to tail; raise loudly if the caller wired this without one.
        self._shipper: RemoteShipper | None = None
        if control_plane_url is not None:
            if not isinstance(self._audit, JsonlAuditSink):
                raise ValueError(
                    "control_plane_url requires audit_log_path "
                    "(remote shipping tails a local JsonlAuditSink)"
                )
            transport = HttpTransport(
                control_plane_url, api_key=api_key, org_slug=org_slug
            )
            offset = self._audit.path.with_suffix(self._audit.path.suffix + ".offset")
            self._shipper = RemoteShipper(self._audit, transport, offset_path=offset)
            self._shipper.start()

    @property
    def shipper(self) -> RemoteShipper | None:
        return self._shipper

    def stop(self) -> None:
        """Stop background workers (audit shipper). Safe to call repeatedly."""
        if self._shipper is not None:
            self._shipper.stop()

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
