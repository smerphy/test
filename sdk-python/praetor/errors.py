from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from praetor_engine.types import DecisionResult


class PraetorError(Exception):
    """Base class for SDK errors."""


class PolicyDenied(PraetorError):
    """Raised when a policy decision blocks a tool call (deny / unhandled approval)."""

    def __init__(self, decision: DecisionResult) -> None:
        self.decision = decision
        super().__init__(
            f"tool call blocked: {decision.decision.value} "
            f"(policy={decision.matched_policy_id}; reason={decision.reason})"
        )


class ApprovalTimeout(PraetorError):
    """Raised when an approval request was not resolved before the timeout."""


class AuditError(PraetorError):
    """Raised when an audit log operation fails (chain corruption, disk failure)."""


__all__ = ["ApprovalTimeout", "AuditError", "PolicyDenied", "PraetorError"]
