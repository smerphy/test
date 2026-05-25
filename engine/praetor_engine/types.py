from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

_STRICT_MODEL = ConfigDict(extra="forbid", frozen=True)


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    TRANSFORM = "transform"

    @classmethod
    def precedence(cls) -> tuple["Decision", ...]:
        # Higher index = higher precedence. The evaluator uses this to
        # resolve conflicts when multiple policies match a single input.
        return (cls.ALLOW, cls.TRANSFORM, cls.REQUIRE_APPROVAL, cls.DENY)


class AgentInfo(BaseModel):
    model_config = _STRICT_MODEL

    id: str = Field(..., min_length=1, description="Stable agent identifier.")
    name: str | None = Field(default=None, description="Human-readable agent name.")
    version: str | None = Field(default=None, description="Agent build / model version.")


class ToolCall(BaseModel):
    model_config = _STRICT_MODEL

    name: str = Field(..., min_length=1, description="Tool name the agent is invoking.")
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments the agent passed to the tool.",
    )
    tool_use_id: str | None = Field(
        default=None,
        description="Provider-specific tool_use id (e.g. Anthropic tool_use block id).",
    )


class SessionInfo(BaseModel):
    model_config = _STRICT_MODEL

    id: str = Field(..., min_length=1, description="Session identifier.")
    started_at: datetime | None = Field(
        default=None, description="Session start timestamp (UTC)."
    )
    parent_agent_ids: list[str] = Field(
        default_factory=list,
        description="Chain of parent agent ids, oldest first. Empty for top-level agents.",
    )


class PolicyInput(BaseModel):
    """Input passed to the policy evaluator for a single tool-call decision."""

    model_config = _STRICT_MODEL

    agent: AgentInfo
    tool: ToolCall
    session: SessionInfo
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form context (user, tenant, environment, request metadata).",
    )


class DecisionResult(BaseModel):
    """Result of evaluating a `PolicyInput` against a policy bundle."""

    model_config = _STRICT_MODEL

    decision: Decision
    reason: str = Field(..., min_length=1, description="Human-readable explanation.")
    matched_policy_id: str | None = Field(
        default=None,
        description="Id of the policy whose effect was applied. None if no policy matched.",
    )
    suggested_transform: dict[str, Any] | None = Field(
        default=None,
        description="Replacement tool arguments. Only set when decision == TRANSFORM.",
    )


__all__ = [
    "AgentInfo",
    "Decision",
    "DecisionResult",
    "PolicyInput",
    "SessionInfo",
    "ToolCall",
]
