"""Policy backtesting: replay audit events through a candidate bundle."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from ephorate_engine.audit_hash import compute_hash as _canonical_hash
from ephorate_engine.parser import PolicyParseError
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Organization
from app.schemas import AuditEventIn
from app.services.audit_ingest import ingest_event
from app.services.backtest import backtest_policy

GENESIS = "0" * 64

# Candidate bundle: allow http.get, deny fs.delete. Everything else default-denies.
_CANDIDATE = """
policies:
  - id: allow-get
    effect: allow
    when: { op: eq, path: tool.name, value: http.get }
    reason: reads allowed
  - id: deny-delete
    effect: deny
    when: { op: eq, path: tool.name, value: fs.delete }
    reason: destructive blocked
"""


def _ingest(
    session: Session,
    org: Organization,
    *,
    seq: int,
    prev_hash: str,
    tool_name: str,
    decision: str,
) -> str:
    raw: dict[str, Any] = {
        "seq": seq,
        "timestamp": datetime(2026, 1, 1, 0, 0, seq, tzinfo=UTC).isoformat(),
        "agent_id": "agent-1",
        "session_id": "s1",
        "tool_name": tool_name,
        "tool_use_id": None,
        "tool_arguments": {"x": 1},
        "decision": decision,
        "reason": "recorded",
        "matched_policy_id": "p0",
        "suggested_transform": None,
        "context": {},
        "evaluator_version": "0.1.0",
        "prev_hash": prev_hash,
        "hash": GENESIS,
    }
    placeholder = AuditEventIn.model_validate(raw)
    raw["hash"] = _canonical_hash(placeholder.model_dump(mode="json", exclude={"hash"}))
    row = ingest_event(session, org_id=org.id, event=AuditEventIn.model_validate(raw))
    return row.hash


def _seed(session: Session, org: Organization) -> None:
    h0 = _ingest(session, org, seq=0, prev_hash=GENESIS, tool_name="http.get", decision="allow")
    _ingest(session, org, seq=1, prev_hash=h0, tool_name="fs.delete", decision="allow")
    session.commit()


def test_backtest_diffs_decisions(session: Session, org: Organization) -> None:
    _seed(session, org)
    report = backtest_policy(session, org.id, yaml_text=_CANDIDATE)

    assert report["evaluated"] == 2
    s = report["summary"]
    assert s["unchanged"] == 1          # http.get stays allow
    assert s["changed"] == 1            # fs.delete allow -> deny
    assert s["newly_denied"] == 1
    assert s["more_restrictive"] == 1
    assert s["less_restrictive"] == 0
    assert report["transitions"] == {"allow->deny": 1}

    ex = report["examples"]
    assert len(ex) == 1
    assert ex[0]["tool_name"] == "fs.delete"
    assert (ex[0]["old_decision"], ex[0]["new_decision"]) == ("allow", "deny")
    assert ex[0]["new_policy_id"] == "deny-delete"


def test_backtest_empty_window(session: Session, org: Organization) -> None:
    report = backtest_policy(session, org.id, yaml_text=_CANDIDATE)
    assert report["evaluated"] == 0
    assert report["summary"]["changed"] == 0
    assert report["examples"] == []


def test_backtest_since_filter(session: Session, org: Organization) -> None:
    _seed(session, org)
    # Window after both events -> nothing evaluated.
    report = backtest_policy(
        session, org.id, yaml_text=_CANDIDATE, since=datetime(2026, 6, 1, tzinfo=UTC)
    )
    assert report["evaluated"] == 0


def test_backtest_invalid_bundle_raises(session: Session, org: Organization) -> None:
    with pytest.raises(PolicyParseError):
        backtest_policy(session, org.id, yaml_text="policies: [ {id: x} ]")


# --- endpoint ---------------------------------------------------------------
def test_backtest_endpoint(client: TestClient, session: Session, org: Organization) -> None:
    _seed(session, org)
    r = client.post("/policies/backtest", json={"yaml_text": _CANDIDATE})
    assert r.status_code == 200
    body = r.json()
    assert body["evaluated"] == 2
    assert body["summary"]["newly_denied"] == 1


def test_backtest_endpoint_rejects_bad_yaml(client: TestClient) -> None:
    r = client.post("/policies/backtest", json={"yaml_text": "policies: [ {id: x} ]"})
    assert r.status_code == 422
    assert "invalid policy bundle" in r.json()["detail"]
