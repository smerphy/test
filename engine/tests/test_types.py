from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from praetor_engine.types import (
    AgentInfo,
    Decision,
    DecisionResult,
    PolicyInput,
    SessionInfo,
    ToolCall,
)


def _input(**overrides: object) -> PolicyInput:
    base = {
        "agent": AgentInfo(id="agent-1", name="researcher", version="claude-x"),
        "tool": ToolCall(name="http.get", arguments={"url": "https://example.com"}),
        "session": SessionInfo(
            id="sess-1",
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            parent_agent_ids=["root"],
        ),
        "context": {"tenant": "acme"},
    }
    base.update(overrides)
    return PolicyInput(**base)  # type: ignore[arg-type]


class TestDecision:
    def test_values_are_stable_strings(self) -> None:
        assert Decision.ALLOW.value == "allow"
        assert Decision.DENY.value == "deny"
        assert Decision.REQUIRE_APPROVAL.value == "require_approval"
        assert Decision.TRANSFORM.value == "transform"

    def test_precedence_order(self) -> None:
        order = Decision.precedence()
        assert order.index(Decision.DENY) > order.index(Decision.REQUIRE_APPROVAL)
        assert order.index(Decision.REQUIRE_APPROVAL) > order.index(Decision.TRANSFORM)
        assert order.index(Decision.TRANSFORM) > order.index(Decision.ALLOW)
        assert set(order) == set(Decision)


class TestPolicyInput:
    def test_constructs_with_required_fields(self) -> None:
        pi = _input()
        assert pi.agent.id == "agent-1"
        assert pi.tool.name == "http.get"
        assert pi.session.id == "sess-1"
        assert pi.context == {"tenant": "acme"}

    def test_context_defaults_to_empty_dict(self) -> None:
        pi = PolicyInput(
            agent=AgentInfo(id="a"),
            tool=ToolCall(name="t"),
            session=SessionInfo(id="s"),
        )
        assert pi.context == {}

    def test_rejects_extra_top_level_fields(self) -> None:
        with pytest.raises(ValidationError):
            PolicyInput(  # type: ignore[call-arg]
                agent=AgentInfo(id="a"),
                tool=ToolCall(name="t"),
                session=SessionInfo(id="s"),
                extra_field="boom",
            )

    def test_is_frozen(self) -> None:
        pi = _input()
        with pytest.raises(ValidationError):
            pi.context = {"mutated": True}  # type: ignore[misc]

    def test_rejects_empty_agent_id(self) -> None:
        with pytest.raises(ValidationError):
            AgentInfo(id="")

    def test_rejects_empty_tool_name(self) -> None:
        with pytest.raises(ValidationError):
            ToolCall(name="")


class TestDecisionResult:
    def test_minimal_allow(self) -> None:
        r = DecisionResult(decision=Decision.ALLOW, reason="default")
        assert r.decision is Decision.ALLOW
        assert r.matched_policy_id is None
        assert r.suggested_transform is None

    def test_transform_carries_replacement_args(self) -> None:
        r = DecisionResult(
            decision=Decision.TRANSFORM,
            reason="redact pii",
            matched_policy_id="redact-emails",
            suggested_transform={"body": "<redacted>"},
        )
        assert r.suggested_transform == {"body": "<redacted>"}

    def test_reason_required_nonempty(self) -> None:
        with pytest.raises(ValidationError):
            DecisionResult(decision=Decision.DENY, reason="")

    def test_is_frozen(self) -> None:
        r = DecisionResult(decision=Decision.ALLOW, reason="ok")
        with pytest.raises(ValidationError):
            r.decision = Decision.DENY  # type: ignore[misc]


class TestJsonSchemaExport:
    def test_policy_input_schema_lists_required_fields(self) -> None:
        schema = PolicyInput.model_json_schema()
        assert set(schema["required"]) == {"agent", "tool", "session"}
        assert schema["additionalProperties"] is False
        assert "agent" in schema["properties"]
        assert "tool" in schema["properties"]
        assert "session" in schema["properties"]
        assert "context" in schema["properties"]

    def test_decision_result_schema_includes_enum(self) -> None:
        schema = DecisionResult.model_json_schema()
        # Pydantic emits the enum via $defs; the property references it.
        defs = schema.get("$defs", {})
        assert "Decision" in defs
        assert set(defs["Decision"]["enum"]) == {
            "allow",
            "deny",
            "require_approval",
            "transform",
        }

    def test_export_helper_returns_all_public_types(self) -> None:
        from praetor_engine.schema import export_schemas

        schemas = export_schemas()
        assert set(schemas) == {"PolicyInput", "DecisionResult"}

    def test_write_schemas_emits_files(self, tmp_path: object) -> None:
        from pathlib import Path

        from praetor_engine.schema import write_schemas

        assert isinstance(tmp_path, Path)
        written = write_schemas(tmp_path)
        names = {p.name for p in written}
        assert names == {"PolicyInput.schema.json", "DecisionResult.schema.json"}
        for p in written:
            assert p.read_text().startswith("{")
