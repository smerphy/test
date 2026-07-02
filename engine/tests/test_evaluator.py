"""Evaluator contract tests.

Covers the Phase 1 spec contract: precedence ordering, deterministic
tie-breaking, default-deny when no policy matches, side-effect freedom,
missing path handling, transform routing, and metadata pass-through.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from praetor_engine.evaluator import Evaluator, Policy
from praetor_engine.predicates import (
    AlwaysPredicate,
    AndPredicate,
    EqPredicate,
    InPredicate,
    MatchesPredicate,
    NotPredicate,
    OrPredicate,
)
from praetor_engine.types import (
    AgentInfo,
    Decision,
    PolicyInput,
    SessionInfo,
    ToolCall,
)


def _input(tool_name: str = "http.get", **tool_args: object) -> PolicyInput:
    return PolicyInput(
        agent=AgentInfo(id="agent-1"),
        tool=ToolCall(
            name=tool_name,
            arguments={"url": "https://example.com", **tool_args},
        ),
        session=SessionInfo(id="sess-1"),
    )


def _eq(path: str, value: object) -> EqPredicate:
    return EqPredicate(path=path, value=value)  # type: ignore[arg-type]


class TestPolicyShape:
    def test_transform_requires_transform_field(self) -> None:
        with pytest.raises(ValidationError) as exc:
            Policy(
                id="t",
                effect=Decision.TRANSFORM,
                when=AlwaysPredicate(),
                reason="r",
            )
        assert "transform" in str(exc.value)

    def test_non_transform_cannot_carry_transform(self) -> None:
        with pytest.raises(ValidationError) as exc:
            Policy(
                id="t",
                effect=Decision.ALLOW,
                when=AlwaysPredicate(),
                reason="r",
                transform={"x": 1},
            )
        assert "transform" in str(exc.value)

    def test_metadata_defaults_empty(self) -> None:
        p = Policy(
            id="p", effect=Decision.ALLOW, when=AlwaysPredicate(), reason="r"
        )
        assert p.metadata == {}

    def test_policy_frozen(self) -> None:
        p = Policy(
            id="p", effect=Decision.ALLOW, when=AlwaysPredicate(), reason="r"
        )
        with pytest.raises(ValidationError):
            p.id = "x"  # type: ignore[misc]


class TestPrecedence:
    def test_no_policies_returns_default_deny(self) -> None:
        result = Evaluator(policies=[]).evaluate(_input())
        assert result.decision is Decision.DENY
        assert result.matched_policy_id is None
        assert result.reason.startswith("default deny")

    def test_single_allow_match(self) -> None:
        policy = Policy(
            id="allow-http-get",
            effect=Decision.ALLOW,
            when=_eq("tool.name", "http.get"),
            reason="http.get is on the allowlist",
        )
        result = Evaluator(policies=[policy]).evaluate(_input())
        assert result.decision is Decision.ALLOW
        assert result.matched_policy_id == "allow-http-get"

    def test_deny_beats_allow(self) -> None:
        allow = Policy(
            id="allow-all",
            effect=Decision.ALLOW,
            when=AlwaysPredicate(),
            reason="allow",
        )
        deny = Policy(
            id="deny-http-get",
            effect=Decision.DENY,
            when=_eq("tool.name", "http.get"),
            reason="blocked",
        )
        result = Evaluator(policies=[allow, deny]).evaluate(_input())
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "deny-http-get"

    def test_require_approval_beats_transform_and_allow(self) -> None:
        allow = Policy(
            id="allow",
            effect=Decision.ALLOW,
            when=AlwaysPredicate(),
            reason="allow",
        )
        transform = Policy(
            id="transform",
            effect=Decision.TRANSFORM,
            when=_eq("tool.name", "http.get"),
            reason="redact",
            transform={"url": "<redacted>"},
        )
        approval = Policy(
            id="approval",
            effect=Decision.REQUIRE_APPROVAL,
            when=_eq("tool.name", "http.get"),
            reason="needs human",
        )
        result = Evaluator(policies=[allow, transform, approval]).evaluate(
            _input()
        )
        assert result.decision is Decision.REQUIRE_APPROVAL
        assert result.matched_policy_id == "approval"
        # Approval doesn't carry a transform; the result shouldn't either.
        assert result.suggested_transform is None

    def test_transform_beats_allow_and_carries_replacement(self) -> None:
        allow = Policy(
            id="allow",
            effect=Decision.ALLOW,
            when=AlwaysPredicate(),
            reason="allow",
        )
        transform = Policy(
            id="redact",
            effect=Decision.TRANSFORM,
            when=_eq("tool.name", "http.get"),
            reason="redact url",
            transform={"url": "<redacted>"},
        )
        result = Evaluator(policies=[allow, transform]).evaluate(_input())
        assert result.decision is Decision.TRANSFORM
        assert result.matched_policy_id == "redact"
        assert result.suggested_transform == {"url": "<redacted>"}

    def test_ties_within_tier_resolve_to_first_declared(self) -> None:
        deny_a = Policy(
            id="deny-a",
            effect=Decision.DENY,
            when=AlwaysPredicate(),
            reason="first deny",
        )
        deny_b = Policy(
            id="deny-b",
            effect=Decision.DENY,
            when=AlwaysPredicate(),
            reason="second deny",
        )
        result = Evaluator(policies=[deny_a, deny_b]).evaluate(_input())
        assert result.matched_policy_id == "deny-a"


class TestPredicateEvaluation:
    def test_eq_matches_top_level_field(self) -> None:
        p = Policy(id="p", effect=Decision.ALLOW, when=_eq("agent.id", "agent-1"), reason="r")
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.ALLOW

    def test_eq_matches_dict_value_via_dotted_path(self) -> None:
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=_eq("tool.arguments.url", "https://example.com"),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.ALLOW

    def test_missing_path_evaluates_to_false(self) -> None:
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=_eq("agent.nonexistent", "x"),
            reason="r",
        )
        result = Evaluator(policies=[p]).evaluate(_input())
        assert result.decision is Decision.DENY  # default-deny
        assert result.matched_policy_id is None

    def test_in_predicate(self) -> None:
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=InPredicate(
                path="tool.name", values=["http.get", "http.post"]
            ),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.ALLOW

    def test_in_predicate_no_match(self) -> None:
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=InPredicate(path="tool.name", values=["fs.read"]),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.DENY

    def test_matches_predicate_on_string(self) -> None:
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=MatchesPredicate(path="tool.arguments.url", pattern=r"^https://"),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.ALLOW

    def test_matches_predicate_non_string_value_is_false(self) -> None:
        # parent_agent_ids is a list, matches expects a string
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=MatchesPredicate(path="session.parent_agent_ids", pattern=r".+"),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.DENY

    def test_and_predicate_short_circuits(self) -> None:
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=AndPredicate(
                clauses=[
                    _eq("tool.name", "http.get"),
                    _eq("agent.id", "agent-1"),
                ]
            ),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.ALLOW

    def test_and_fails_when_any_clause_false(self) -> None:
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=AndPredicate(
                clauses=[_eq("tool.name", "http.get"), _eq("agent.id", "other")]
            ),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.DENY

    def test_or_predicate(self) -> None:
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=OrPredicate(
                clauses=[_eq("tool.name", "fs.read"), _eq("tool.name", "http.get")]
            ),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.ALLOW

    def test_not_predicate(self) -> None:
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=NotPredicate(clause=_eq("tool.name", "fs.read")),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.ALLOW

    def test_not_on_missing_path_is_true(self) -> None:
        # Documented edge: not(missing) == not(false) == true.
        p = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=NotPredicate(clause=_eq("agent.nonexistent", "x")),
            reason="r",
        )
        assert Evaluator(policies=[p]).evaluate(_input()).decision is Decision.ALLOW


class TestSideEffectFreedom:
    def test_evaluator_is_idempotent(self) -> None:
        policy = Policy(
            id="p",
            effect=Decision.ALLOW,
            when=_eq("tool.name", "http.get"),
            reason="ok",
        )
        ev = Evaluator(policies=[policy])
        pi = _input()
        before = pi.model_dump()
        r1 = ev.evaluate(pi)
        r2 = ev.evaluate(pi)
        assert r1 == r2
        assert pi.model_dump() == before

    def test_policies_property_is_tuple(self) -> None:
        policy = Policy(
            id="p", effect=Decision.ALLOW, when=AlwaysPredicate(), reason="r"
        )
        ev = Evaluator(policies=[policy])
        assert isinstance(ev.policies, tuple)
        assert ev.policies == (policy,)


class TestMalformedInputs:
    def test_extra_field_on_policy_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Policy(  # type: ignore[call-arg]
                id="p",
                effect=Decision.ALLOW,
                when=AlwaysPredicate(),
                reason="r",
                rogue=True,
            )

    def test_missing_required_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Policy.model_validate(  # missing reason
                {"id": "p", "effect": "allow", "when": {"op": "always"}}
            )

    def test_unknown_effect_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Policy.model_validate(
                {
                    "id": "p",
                    "effect": "audit",
                    "when": {"op": "always"},
                    "reason": "r",
                }
            )
