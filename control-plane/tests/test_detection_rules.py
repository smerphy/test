from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditEvent, DetectionRule, Finding, Organization
from app.services.detections import run_detections

_SEQ = [0]


def _audit(
    session: Session,
    org: Organization,
    *,
    decision: str = "deny",
    matched_policy_id: str | None = None,
    tool_name: str = "http.post",
    session_id: str = "s1",
) -> None:
    _SEQ[0] += 1
    session.add(
        AuditEvent(
            organization_id=org.id,
            seq=_SEQ[0],
            timestamp=datetime.now(UTC) - timedelta(minutes=1),
            agent_id="agent-1",
            session_id=session_id,
            tool_name=tool_name,
            tool_arguments={},
            decision=decision,
            reason="r",
            matched_policy_id=matched_policy_id,
            context={},
            evaluator_version="0.1.0",
            prev_hash="0" * 64,
            hash=f"{_SEQ[0]:064d}",
        )
    )
    session.commit()


def _valid_rule_body() -> dict:
    return {
        "name": "shell-exec-attempts",
        "description": "flag shell tool denials",
        "severity": "high",
        "category": "abuse",
        "spec": {
            "decision": "deny",
            "tool_name": "shell.exec",
            "group_by": "agent",
            "threshold": 2,
        },
        "owasp_llm": "LLM01",
    }


def test_crud_detection_rule(client: TestClient) -> None:
    created = client.post("/detection-rules", json=_valid_rule_body())
    assert created.status_code == 201
    rid = created.json()["id"]
    assert created.json()["spec"]["threshold"] == 2

    assert len(client.get("/detection-rules").json()) == 1
    assert client.get(f"/detection-rules/{rid}").json()["name"] == "shell-exec-attempts"

    upd = _valid_rule_body()
    upd["enabled"] = False
    assert client.put(f"/detection-rules/{rid}", json=upd).json()["enabled"] is False

    assert client.delete(f"/detection-rules/{rid}").status_code == 204
    assert client.get("/detection-rules").json() == []


def test_duplicate_name_conflicts(client: TestClient) -> None:
    client.post("/detection-rules", json=_valid_rule_body())
    assert client.post("/detection-rules", json=_valid_rule_body()).status_code == 409


def test_spec_requires_a_condition(client: TestClient) -> None:
    body = _valid_rule_body()
    body["spec"] = {"group_by": "agent", "threshold": 1}  # no match condition
    assert client.post("/detection-rules", json=body).status_code == 422


def test_custom_rule_produces_findings(
    session: Session, org: Organization
) -> None:
    session.add(
        DetectionRule(
            organization_id=org.id,
            name="shell-denials",
            enabled=True,
            severity="high",
            category="abuse",
            spec={
                "decision": "deny",
                "tool_name": "shell.exec",
                "group_by": "agent",
                "threshold": 2,
            },
            owasp_llm="LLM01",
        )
    )
    session.commit()

    # Two matching events -> fires; a non-matching event is ignored.
    _audit(session, org, decision="deny", tool_name="shell.exec")
    _audit(session, org, decision="deny", tool_name="shell.exec")
    _audit(session, org, decision="allow", tool_name="shell.exec")

    run_detections(session, org_id=org.id)
    session.commit()
    fs = [
        f
        for f in session.query(Finding).filter(Finding.organization_id == org.id)
        if f.rule_id == "shell-denials"
    ]
    assert len(fs) == 1
    assert fs[0].count == 2
    assert fs[0].owasp_llm == "LLM01"


def test_custom_rule_below_threshold_no_finding(
    session: Session, org: Organization
) -> None:
    session.add(
        DetectionRule(
            organization_id=org.id,
            name="single-deny",
            enabled=True,
            severity="low",
            category="policy_violation",
            spec={"decision": "deny", "group_by": "agent", "threshold": 5},
        )
    )
    session.commit()
    _audit(session, org, decision="deny")
    run_detections(session, org_id=org.id)
    session.commit()
    assert not [
        f
        for f in session.query(Finding).filter(Finding.organization_id == org.id)
        if f.rule_id == "single-deny"
    ]
