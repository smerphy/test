"""Policy evaluator — stub.

The evaluator is intentionally unimplemented. `tests/test_evaluator.py`
captures the contract; implement until those tests pass.

Spec contract (Phase 1, items 3-4):
  - deterministic, side-effect-free
  - returns the highest-priority matching decision
    (deny > require_approval > transform > allow)
  - returns `DecisionResult(decision=DENY, matched_policy_id=None, ...)`
    when no policy matches (default-deny posture)
  - sub-5ms p99 on a 100-policy bundle
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from praetor_engine.types import Decision, DecisionResult, PolicyInput


class Policy(BaseModel):
    """A single declarative policy. Surface shape only — semantics live in `Evaluator`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1)
    effect: Decision
    when: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(..., min_length=1)


class Evaluator:
    def __init__(self, policies: Sequence[Policy]) -> None:
        self._policies = tuple(policies)

    def evaluate(self, policy_input: PolicyInput) -> DecisionResult:
        raise NotImplementedError(
            "Evaluator.evaluate is not implemented yet — see tests/test_evaluator.py"
        )


__all__ = ["Evaluator", "Policy"]
