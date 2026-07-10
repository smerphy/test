"""Policy evaluator.

Pure, side-effect-free evaluation of a policy bundle against a single
`PolicyInput`. Resolves the highest-precedence matching effect across
the bundle: deny > require_approval > transform > allow. When no
policy matches, returns a default-deny `DecisionResult`.

Within the highest-precedence tier, the first policy in declaration
order wins (deterministic tie-breaking).
"""

from __future__ import annotations

import functools
import re
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ephorate_engine.predicates import (
    AlwaysPredicate,
    AndPredicate,
    EqPredicate,
    InPredicate,
    MatchesPredicate,
    NotPredicate,
    OrPredicate,
    Predicate,
)
from ephorate_engine.types import Decision, DecisionResult, PolicyInput


class Policy(BaseModel):
    """A single declarative policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1)
    effect: Decision
    when: Predicate
    reason: str = Field(..., min_length=1)
    transform: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Replacement tool arguments. Required iff effect == TRANSFORM. "
            "MVP shape: a static dict; will likely grow into a path/template "
            "DSL once we have real workloads to learn from."
        ),
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Free-form metadata. Convention: framework control mappings "
            "(e.g. {'nist_ai_rmf': 'GOVERN-1.1'}). Carried through to audit logs."
        ),
    )

    @model_validator(mode="after")
    def _check_transform(self) -> Policy:
        if self.effect is Decision.TRANSFORM and self.transform is None:
            raise ValueError("effect=transform requires a transform field")
        if self.effect is not Decision.TRANSFORM and self.transform is not None:
            raise ValueError("transform is only valid when effect=transform")
        return self


_DECISION_RANK: dict[Decision, int] = {
    d: i for i, d in enumerate(Decision.precedence())
}


@functools.lru_cache(maxsize=4096)
def _compile_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# Sentinel for "path did not resolve". Using a unique object means a
# legitimately-`None` value at a path is not confused with "missing".
_MISSING: Any = object()

# Cap on the input length a `matches` regex evaluates, bounding worst-case
# backtracking on adversarially long agent-supplied strings.
_MAX_MATCH_INPUT = 8192


def _resolve_path(policy_input: PolicyInput, path: str) -> Any:
    """Walk a dotted path into a PolicyInput. Returns `_MISSING` if any segment fails.

    Handles two node kinds: Pydantic models (attribute lookup with a
    `model_fields` membership guard so attribute typos don't accidentally
    succeed) and dicts (key lookup).
    """
    current: Any = policy_input
    for part in path.split("."):
        if isinstance(current, BaseModel):
            if part not in type(current).model_fields:
                return _MISSING
            current = getattr(current, part)
        elif isinstance(current, dict):
            if part not in current:
                return _MISSING
            current = current[part]
        else:
            return _MISSING
    return current


def _eval(predicate: Predicate, policy_input: PolicyInput) -> bool:
    if isinstance(predicate, AlwaysPredicate):
        return True
    if isinstance(predicate, EqPredicate):
        value = _resolve_path(policy_input, predicate.path)
        return value is not _MISSING and value == predicate.value
    if isinstance(predicate, InPredicate):
        value = _resolve_path(policy_input, predicate.path)
        return value is not _MISSING and value in predicate.values
    if isinstance(predicate, MatchesPredicate):
        value = _resolve_path(policy_input, predicate.path)
        if value is _MISSING or not isinstance(value, str):
            return False
        # Bound the input the (author-supplied) regex runs against so a
        # pathological pattern can't be amplified into catastrophic
        # backtracking by an agent supplying a very long string.
        return bool(
            _compile_regex(predicate.pattern).search(value[:_MAX_MATCH_INPUT])
        )
    if isinstance(predicate, AndPredicate):
        return all(_eval(c, policy_input) for c in predicate.clauses)
    if isinstance(predicate, OrPredicate):
        return any(_eval(c, policy_input) for c in predicate.clauses)
    if isinstance(predicate, NotPredicate):
        return not _eval(predicate.clause, policy_input)
    raise AssertionError(  # pragma: no cover - unreachable given the union
        f"unhandled predicate type: {type(predicate).__name__}"
    )


class Evaluator:
    """Evaluate a fixed bundle of policies against `PolicyInput`s.

    Construction-time work: freeze the policy tuple. Per-call work: one
    pass over policies, short-circuited predicate evaluation, no
    allocations beyond the returned `DecisionResult`. Thread-safe.
    """

    __slots__ = ("_policies",)

    def __init__(self, policies: Sequence[Policy]) -> None:
        self._policies: tuple[Policy, ...] = tuple(policies)

    @property
    def policies(self) -> tuple[Policy, ...]:
        return self._policies

    def evaluate(self, policy_input: PolicyInput) -> DecisionResult:
        winner: Policy | None = None
        winner_rank = -1
        for policy in self._policies:
            if not _eval(policy.when, policy_input):
                continue
            rank = _DECISION_RANK[policy.effect]
            if rank > winner_rank:
                winner = policy
                winner_rank = rank
        if winner is None:
            return DecisionResult(
                decision=Decision.DENY,
                reason="default deny: no policy matched",
            )
        return DecisionResult(
            decision=winner.effect,
            reason=winner.reason,
            matched_policy_id=winner.id,
            suggested_transform=winner.transform,
        )


__all__ = ["Evaluator", "Policy"]
