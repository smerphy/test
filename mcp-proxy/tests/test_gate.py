"""PolicyGate decision mapping — the tested proxy core."""

from __future__ import annotations

from typing import Any

from praetor import PraetorClient
from praetor_engine.evaluator import Policy
from praetor_engine.predicates import EqPredicate
from praetor_engine.types import Decision

from praetor_mcp.gate import PolicyGate


def _policies() -> list[Policy]:
    return [
        Policy(
            id="allow-get",
            effect=Decision.ALLOW,
            when=EqPredicate(path="tool.name", value="github__get"),
            reason="reads allowed",
        ),
        Policy(
            id="deny-delete",
            effect=Decision.DENY,
            when=EqPredicate(path="tool.name", value="fs__delete"),
            reason="destructive tool blocked",
        ),
        Policy(
            id="redact-write",
            effect=Decision.TRANSFORM,
            when=EqPredicate(path="tool.name", value="fs__write"),
            reason="path constrained",
            transform={"path": "/sandbox"},
        ),
    ]


def _gate(on_error: str = "deny") -> PolicyGate:
    client = PraetorClient(policies=_policies(), default_agent_id="agent-1")
    return PolicyGate(client, on_error=on_error)


def test_allow_forwards_unchanged() -> None:
    r = _gate().gate_tool_call(
        tool="get", server="github", arguments={"repo": "x"}, session_id="s1"
    )
    assert r.allow is True
    assert r.decision == "allow"
    assert r.arguments == {"repo": "x"}
    assert r.policy_id == "allow-get"


def test_deny_blocks_with_reason() -> None:
    r = _gate().gate_tool_call(
        tool="delete", server="fs", arguments={"path": "/etc"}, session_id="s1"
    )
    assert r.allow is False
    assert r.is_error is True
    assert r.decision == "deny"
    assert "destructive tool blocked" in r.error_text()
    assert "deny-delete" in r.error_text()


def test_transform_rewrites_arguments() -> None:
    r = _gate().gate_tool_call(
        tool="write",
        server="fs",
        arguments={"path": "/etc/passwd", "data": "x"},
        session_id="s1",
    )
    assert r.allow is True
    assert r.decision == "transform"
    # transform overrides path, preserves other args.
    assert r.arguments == {"path": "/sandbox", "data": "x"}


def test_unmatched_tool_is_default_denied() -> None:
    r = _gate().gate_tool_call(
        tool="anything", server="misc", arguments={}, session_id="s1"
    )
    assert r.allow is False
    assert r.decision == "deny"


def test_fail_closed_and_open_on_evaluation_error() -> None:
    class BoomClient:
        policies: tuple[Any, ...] = ()

        def evaluate(self, *a: Any, **k: Any) -> Any:
            raise RuntimeError("boom")

    closed = PolicyGate(BoomClient(), on_error="deny").gate_tool_call(
        tool="t", arguments={}, session_id="s"
    )
    assert closed.allow is False and "fail-closed" in closed.reason

    opened = PolicyGate(BoomClient(), on_error="allow").gate_tool_call(
        tool="t", arguments={}, session_id="s"
    )
    assert opened.allow is True and "fail-open" in opened.reason


def test_tool_visibility_filtering() -> None:
    gate = _gate()
    assert gate.is_tool_visible("get", server="github", session_id="s") is True
    assert gate.is_tool_visible("delete", server="fs", session_id="s") is False
    # No matching policy -> default deny -> hidden.
    assert gate.is_tool_visible("random", server="misc", session_id="s") is False


def test_invalid_on_error_rejected() -> None:
    import pytest

    with pytest.raises(ValueError, match="on_error"):
        _gate(on_error="maybe")
