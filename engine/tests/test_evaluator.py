"""Failing contract tests for the evaluator.

The evaluator itself is intentionally not implemented yet — these tests
codify the contract from the spec (Phase 1, items 3-4):

  - deterministic, side-effect-free
  - returns the highest-priority matching decision
    (deny > require_approval > transform > allow)
  - default decision when no policy matches
  - explicit `matched_policy_id` on the returned result

They currently fail with NotImplementedError. Implement the evaluator
until they pass.
"""

from __future__ import annotations

import pytest

from praetor_engine import evaluator
from praetor_engine.predicates import AlwaysPredicate, EqPredicate
from praetor_engine.types import (
    AgentInfo,
    Decision,
    PolicyInput,
    SessionInfo,
    ToolCall,
)

pytestmark = pytest.mark.xfail(
    strict=True,
    raises=NotImplementedError,
    reason="evaluator stub — remove this marker when Evaluator.evaluate is implemented",
)


def _input(tool_name: str = "http.get") -> PolicyInput:
    return PolicyInput(
        agent=AgentInfo(id="agent-1"),
        tool=ToolCall(name=tool_name, arguments={"url": "https://example.com"}),
        session=SessionInfo(id="sess-1"),
    )


def _eq(path: str, value: str) -> EqPredicate:
    return EqPredicate(path=path, value=value)


class TestEvaluatorContract:
    def test_no_policies_returns_default_deny(self) -> None:
        result = evaluator.Evaluator(policies=[]).evaluate(_input())
        assert result.decision is Decision.DENY
        assert result.matched_policy_id is None

    def test_single_allow_match(self) -> None:
        policy = evaluator.Policy(
            id="allow-http-get",
            effect=Decision.ALLOW,
            when=_eq("tool.name", "http.get"),
            reason="http.get is on the allowlist",
        )
        result = evaluator.Evaluator(policies=[policy]).evaluate(_input())
        assert result.decision is Decision.ALLOW
        assert result.matched_policy_id == "allow-http-get"

    def test_deny_beats_allow(self) -> None:
        allow = evaluator.Policy(
            id="allow-all",
            effect=Decision.ALLOW,
            when=AlwaysPredicate(),
            reason="allow",
        )
        deny = evaluator.Policy(
            id="deny-http-get",
            effect=Decision.DENY,
            when=_eq("tool.name", "http.get"),
            reason="blocked",
        )
        result = evaluator.Evaluator(policies=[allow, deny]).evaluate(_input())
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "deny-http-get"

    def test_require_approval_beats_transform_and_allow(self) -> None:
        allow = evaluator.Policy(
            id="allow",
            effect=Decision.ALLOW,
            when=AlwaysPredicate(),
            reason="allow",
        )
        transform = evaluator.Policy(
            id="transform",
            effect=Decision.TRANSFORM,
            when=_eq("tool.name", "http.get"),
            reason="redact",
        )
        approval = evaluator.Policy(
            id="approval",
            effect=Decision.REQUIRE_APPROVAL,
            when=_eq("tool.name", "http.get"),
            reason="needs human",
        )
        result = evaluator.Evaluator(policies=[allow, transform, approval]).evaluate(
            _input()
        )
        assert result.decision is Decision.REQUIRE_APPROVAL
        assert result.matched_policy_id == "approval"

    def test_transform_beats_allow(self) -> None:
        allow = evaluator.Policy(
            id="allow",
            effect=Decision.ALLOW,
            when=AlwaysPredicate(),
            reason="allow",
        )
        transform = evaluator.Policy(
            id="redact",
            effect=Decision.TRANSFORM,
            when=_eq("tool.name", "http.get"),
            reason="redact url",
        )
        result = evaluator.Evaluator(policies=[allow, transform]).evaluate(_input())
        assert result.decision is Decision.TRANSFORM
        assert result.matched_policy_id == "redact"

    def test_evaluation_is_side_effect_free(self) -> None:
        policy = evaluator.Policy(
            id="p",
            effect=Decision.ALLOW,
            when=_eq("tool.name", "http.get"),
            reason="ok",
        )
        ev = evaluator.Evaluator(policies=[policy])
        pi = _input()
        before = pi.model_dump()
        r1 = ev.evaluate(pi)
        r2 = ev.evaluate(pi)
        assert r1 == r2
        assert pi.model_dump() == before

    def test_non_matching_predicate_skipped(self) -> None:
        policy = evaluator.Policy(
            id="only-fs",
            effect=Decision.ALLOW,
            when=_eq("tool.name", "fs.read"),
            reason="fs allowed",
        )
        result = evaluator.Evaluator(policies=[policy]).evaluate(
            _input(tool_name="http.get")
        )
        # No policy matched -> default deny, no matched_policy_id.
        assert result.decision is Decision.DENY
        assert result.matched_policy_id is None
