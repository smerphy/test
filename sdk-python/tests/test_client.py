from __future__ import annotations

from pathlib import Path

import pytest
from praetor_engine.evaluator import Policy
from praetor_engine.predicates import AlwaysPredicate, EqPredicate
from praetor_engine.types import Decision, PolicyInput

from praetor.approval import ApprovalHandler
from praetor.audit import AuditEvent, NullAuditSink
from praetor.client import PraetorClient
from praetor.errors import PolicyDenied


def _allow_policy() -> Policy:
    return Policy(
        id="allow-http",
        effect=Decision.ALLOW,
        when=EqPredicate(path="tool.name", value="http.get"),
        reason="ok",
    )


def _deny_policy() -> Policy:
    return Policy(
        id="deny-http",
        effect=Decision.DENY,
        when=EqPredicate(path="tool.name", value="http.get"),
        reason="nope",
    )


def _transform_policy() -> Policy:
    return Policy(
        id="redact",
        effect=Decision.TRANSFORM,
        when=AlwaysPredicate(),
        reason="redact url",
        transform={"url": "<redacted>"},
    )


def _approval_policy() -> Policy:
    return Policy(
        id="needs-human",
        effect=Decision.REQUIRE_APPROVAL,
        when=AlwaysPredicate(),
        reason="needs human",
    )


class _RecordingSink(NullAuditSink):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, policy_input: PolicyInput, decision) -> AuditEvent:  # type: ignore[override]
        event = super().record(policy_input, decision)
        self.events.append(event)
        return event


class TestConstruction:
    def test_policies_or_bundle_path_required_exclusive(self, tmp_path: Path) -> None:
        bundle = tmp_path / "b.yaml"
        bundle.write_text("policies: []\n")
        with pytest.raises(ValueError):
            PraetorClient(policies=[], bundle_path=bundle)

    def test_loads_from_bundle_path(self, tmp_path: Path) -> None:
        bundle = tmp_path / "b.yaml"
        bundle.write_text(
            "policies:\n"
            "  - id: a\n"
            "    effect: allow\n"
            "    when: {op: always}\n"
            "    reason: r\n"
        )
        c = PraetorClient(bundle_path=bundle, default_agent_id="agent-1")
        assert len(c.policies) == 1
        assert c.policies[0].id == "a"


class TestEvaluate:
    def test_allow_path(self) -> None:
        sink = _RecordingSink()
        c = PraetorClient(
            policies=[_allow_policy()],
            audit_sink=sink,
            default_agent_id="agent-1",
        )
        result = c.evaluate("http.get", {"url": "https://x.com"}, session_id="s1")
        assert result.decision is Decision.ALLOW
        assert result.matched_policy_id == "allow-http"
        assert len(sink.events) == 1
        assert sink.events[0].tool_name == "http.get"

    def test_explicit_agent_id_overrides_default(self) -> None:
        sink = _RecordingSink()
        c = PraetorClient(
            policies=[_allow_policy()],
            audit_sink=sink,
            default_agent_id="default-agent",
        )
        c.evaluate(
            "http.get",
            {"url": "https://x.com"},
            session_id="s1",
            agent_id="explicit-agent",
        )
        assert sink.events[0].agent_id == "explicit-agent"

    def test_missing_agent_raises(self) -> None:
        c = PraetorClient(policies=[_allow_policy()])
        with pytest.raises(ValueError, match="agent_id"):
            c.evaluate("http.get", {}, session_id="s1")

    def test_deny_returns_deny_without_raising(self) -> None:
        c = PraetorClient(
            policies=[_deny_policy()], default_agent_id="a"
        )
        result = c.evaluate("http.get", {}, session_id="s1")
        assert result.decision is Decision.DENY

    def test_default_deny_when_no_match(self) -> None:
        c = PraetorClient(policies=[_allow_policy()], default_agent_id="a")
        result = c.evaluate("fs.read", {}, session_id="s1")
        assert result.decision is Decision.DENY
        assert result.matched_policy_id is None


class TestApprovalFlow:
    class _AlwaysApprove(ApprovalHandler):
        def request_approval(self, policy_input, *, policy_id, reason):  # type: ignore[override]
            return True

    class _AlwaysDeny(ApprovalHandler):
        def request_approval(self, policy_input, *, policy_id, reason):  # type: ignore[override]
            return False

    def test_no_handler_resolves_to_deny(self) -> None:
        c = PraetorClient(
            policies=[_approval_policy()], default_agent_id="a"
        )
        result = c.evaluate("any", {}, session_id="s1")
        assert result.decision is Decision.DENY
        assert "no approval handler" in result.reason

    def test_handler_approves(self) -> None:
        c = PraetorClient(
            policies=[_approval_policy()],
            default_agent_id="a",
            approval_handler=self._AlwaysApprove(),
        )
        result = c.evaluate("any", {}, session_id="s1")
        assert result.decision is Decision.ALLOW
        assert result.matched_policy_id == "needs-human"

    def test_handler_denies(self) -> None:
        c = PraetorClient(
            policies=[_approval_policy()],
            default_agent_id="a",
            approval_handler=self._AlwaysDeny(),
        )
        result = c.evaluate("any", {}, session_id="s1")
        assert result.decision is Decision.DENY


class TestEnforce:
    def test_allow_returns_arguments(self) -> None:
        c = PraetorClient(policies=[_allow_policy()], default_agent_id="a")
        args = c.enforce(
            "http.get", {"url": "https://x.com"}, session_id="s1"
        )
        assert args == {"url": "https://x.com"}

    def test_transform_merges_replacement(self) -> None:
        c = PraetorClient(policies=[_transform_policy()], default_agent_id="a")
        args = c.enforce(
            "http.get",
            {"url": "https://x.com", "extra": "kept"},
            session_id="s1",
        )
        assert args == {"url": "<redacted>", "extra": "kept"}

    def test_deny_raises_policy_denied(self) -> None:
        c = PraetorClient(policies=[_deny_policy()], default_agent_id="a")
        with pytest.raises(PolicyDenied) as exc_info:
            c.enforce("http.get", {}, session_id="s1")
        assert exc_info.value.decision.decision is Decision.DENY
