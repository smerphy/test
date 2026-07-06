"""UEBA baselining: rebuild + drift detection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient
from praetor_engine.audit_hash import compute_hash as _canonical_hash
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AgentBaseline, Finding, Organization
from app.schemas import AuditEventIn
from app.services.audit_ingest import ingest_event
from app.services.baseline import detect_drift, rebuild_baselines

GENESIS = "0" * 64
NOW = datetime(2026, 6, 15, 12, tzinfo=UTC)


class _Chain:
    """Appends a valid per-(agent, session) audit chain."""

    def __init__(self, agent: str = "a", session_id: str = "s1") -> None:
        self.seq = 0
        self.prev = GENESIS
        self.agent = agent
        self.session_id = session_id

    def add(
        self, session: Session, org: Organization, *, tool: str, decision: str,
        ts: datetime,
    ) -> None:
        raw: dict[str, Any] = {
            "seq": self.seq,
            "timestamp": ts.isoformat(),
            "agent_id": self.agent,
            "session_id": self.session_id,
            "tool_name": tool,
            "tool_use_id": None,
            "tool_arguments": {},
            "decision": decision,
            "reason": "r",
            "matched_policy_id": "p",
            "suggested_transform": None,
            "context": {},
            "evaluator_version": "0.1.0",
            "prev_hash": self.prev,
            "hash": GENESIS,
        }
        placeholder = AuditEventIn.model_validate(raw)
        raw["hash"] = _canonical_hash(
            placeholder.model_dump(mode="json", exclude={"hash"})
        )
        row = ingest_event(
            session, org_id=org.id, event=AuditEventIn.model_validate(raw)
        )
        self.prev = row.hash
        self.seq += 1


def _train(session: Session, org: Organization) -> _Chain:
    chain = _Chain()
    old = NOW - timedelta(days=5)
    for i in range(10):
        chain.add(session, org, tool="http.get", decision="allow",
                  ts=old + timedelta(seconds=i))
    for i in range(2):
        chain.add(session, org, tool="fs.read", decision="allow",
                  ts=old + timedelta(seconds=20 + i))
    return chain


# --- rebuild ----------------------------------------------------------------
def test_rebuild_baselines(session: Session, org: Organization) -> None:
    _train(session, org)
    session.commit()
    result = rebuild_baselines(session, org.id, now=NOW)
    assert result == {"agents": 1, "events": 12}

    baseline = session.execute(select(AgentBaseline)).scalar_one()
    assert baseline.agent_id == "a"
    assert baseline.event_count == 12
    assert baseline.tool_counts == {"http.get": 10, "fs.read": 2}
    assert baseline.distinct_tools == 2
    assert baseline.distinct_sessions == 1
    assert baseline.decision_counts == {"allow": 12}


def test_rebuild_is_upsert(session: Session, org: Organization) -> None:
    _train(session, org)
    session.commit()
    rebuild_baselines(session, org.id, now=NOW)
    rebuild_baselines(session, org.id, now=NOW)  # again
    assert len(session.execute(select(AgentBaseline)).scalars().all()) == 1


# --- drift ------------------------------------------------------------------
def test_detect_drift_new_tool_and_deny_spike(
    session: Session, org: Organization
) -> None:
    chain = _train(session, org)
    session.commit()
    rebuild_baselines(session, org.id, now=NOW)
    session.commit()

    # Recent burst: a never-before-seen tool + a spike of denials.
    recent = NOW - timedelta(minutes=10)
    for i in range(3):
        chain.add(session, org, tool="shell.exec", decision="deny",
                  ts=recent + timedelta(seconds=i))
    for i in range(3):
        chain.add(session, org, tool="http.get", decision="deny",
                  ts=recent + timedelta(seconds=10 + i))
    session.commit()

    result = detect_drift(session, org, now=NOW)
    assert result["agents"] == 1
    assert result["findings"] == 2

    findings = {
        f.rule_id: f
        for f in session.execute(select(Finding)).scalars()
    }
    assert "ueba-new-tool" in findings
    assert findings["ueba-new-tool"].severity == "medium"
    assert findings["ueba-new-tool"].evidence["new_tools"] == ["shell.exec"]
    assert "ueba-deny-spike" in findings
    assert findings["ueba-deny-spike"].severity == "high"


def test_detect_drift_ignores_low_volume(
    session: Session, org: Organization
) -> None:
    chain = _train(session, org)
    session.commit()
    rebuild_baselines(session, org.id, now=NOW)
    session.commit()
    # Only 2 recent events (< min threshold) → skipped.
    recent = NOW - timedelta(minutes=5)
    chain.add(session, org, tool="shell.exec", decision="deny", ts=recent)
    chain.add(session, org, tool="shell.exec", decision="deny", ts=recent)
    session.commit()
    result = detect_drift(session, org, now=NOW)
    assert result == {"agents": 0, "findings": 0}


# --- endpoints --------------------------------------------------------------
def test_baseline_endpoints(client: TestClient, session: Session, org: Organization) -> None:
    _train(session, org)
    session.commit()
    assert client.post("/baselines/rebuild").json() == {"agents": 1, "events": 12}
    rows = client.get("/baselines").json()
    assert len(rows) == 1 and rows[0]["agent_id"] == "a"
    assert "findings" in client.post("/baselines/detect").json()
