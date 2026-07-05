from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from praetor_engine.types import (
    AgentInfo,
    Decision,
    DecisionResult,
    PolicyInput,
    SessionInfo,
    ToolCall,
)

from praetor.audit import JsonlAuditSink, verify_chain


def _pi_with_pii() -> PolicyInput:
    return PolicyInput(
        agent=AgentInfo(id="agent-1"),
        tool=ToolCall(
            name="email.send",
            arguments={"to": "bob@corp.com", "body": "ssn 123-45-6789"},
        ),
        session=SessionInfo(id="s1", started_at=datetime(2026, 1, 1, tzinfo=UTC)),
        context={"actor_email": "alice@acme.com"},
    )


def _decision() -> DecisionResult:
    return DecisionResult(
        decision=Decision.ALLOW,
        reason="allowed request from bob@corp.com",
        matched_policy_id="p1",
    )


def test_redacts_before_hash_and_chain_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path, redact_pii=True)
    event = sink.record(_pi_with_pii(), _decision())

    args = json.dumps(event.tool_arguments)
    assert "bob@corp.com" not in args
    assert "123-45-6789" not in args
    assert "bob@corp.com" not in event.reason
    assert "alice@acme.com" not in json.dumps(event.context)

    # The redaction happened pre-hash, so the tamper-evident chain still
    # verifies against the stored (redacted) values.
    assert verify_chain(path) == 1


def test_no_redaction_by_default(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path)
    event = sink.record(_pi_with_pii(), _decision())
    assert "bob@corp.com" in json.dumps(event.tool_arguments)
    assert verify_chain(path) == 1


def test_client_option_wires_redaction(tmp_path: Path) -> None:
    from praetor import PraetorClient

    client = PraetorClient(
        policies=[], audit_log_path=tmp_path / "a.jsonl", redact_pii=True
    )
    event = client._audit.record(_pi_with_pii(), _decision())
    assert "bob@corp.com" not in json.dumps(event.tool_arguments)
