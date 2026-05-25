from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

_STRICT_MODEL = ConfigDict(extra="forbid", frozen=True)


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    TRANSFORM = "transform"

    @classmethod
    def precedence(cls) -> tuple[Decision, ...]:
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
        description="Arguments the agent passed to the tool. Must be JSON-serializable.",
    )
    tool_use_id: str | None = Field(
        default=None,
        description="Provider-specific tool_use id (e.g. Anthropic tool_use block id).",
    )

    @field_validator("arguments")
    @classmethod
    def _json_serializable(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"tool arguments must be JSON-serializable: {exc}"
            ) from exc
        return value


class SessionInfo(BaseModel):
    model_config = _STRICT_MODEL

    id: str = Field(..., min_length=1, description="Session identifier.")
    started_at: AwareDatetime | None = Field(
        default=None,
        description="Session start timestamp. Must be timezone-aware.",
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

    @field_validator("context")
    @classmethod
    def _json_serializable(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"context must be JSON-serializable: {exc}") from exc
        return value


class DecisionResult(BaseModel):
    """Result of evaluating a `PolicyInput` against a policy bundle."""

    model_config = _STRICT_MODEL

    decision: Decision
    reason: str = Field(..., min_length=1, description="Human-readable explanation.")
    matched_policy_id: str | None = Field(
        default=None,
        description=(
            "Id of the policy whose effect was applied. None only for the "
            "default-deny case (no policy matched)."
        ),
    )
    suggested_transform: dict[str, Any] | None = Field(
        default=None,
        description="Replacement tool arguments. Required iff decision == TRANSFORM.",
    )

    @model_validator(mode="after")
    def _check_invariants(self) -> DecisionResult:
        if self.decision is Decision.TRANSFORM and self.suggested_transform is None:
            raise ValueError("decision=transform requires suggested_transform")
        if self.decision is not Decision.TRANSFORM and self.suggested_transform is not None:
            raise ValueError(
                "suggested_transform is only valid when decision=transform"
            )
        if self.decision is not Decision.DENY and self.matched_policy_id is None:
            raise ValueError(
                f"decision={self.decision.value} requires matched_policy_id "
                "(only default-deny may have a null matched_policy_id)"
            )
        return self


__all__ = [
    "AgentInfo",
    "Decision",
    "DecisionResult",
    "PolicyInput",
    "SessionInfo",
    "ToolCall",
]
