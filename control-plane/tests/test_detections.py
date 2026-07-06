from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models import AuditEvent, Finding, FindingCategory, FindingSeverity, Organization
from app.services.detections import run_detections

_SEQ = [0]


def _audit(
    session: Session,
    org: Organization,
    *,
    decision: str = "deny",
    matched_policy_id: str | None = None,
    agent_id: str = "agent-1",
    session_id: str = "sess-1",
    tool_name: str = "http.post",
    minutes_ago: float = 1.0,
) -> AuditEvent:
    _SEQ[0] += 1
    ts = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    ev = AuditEvent(
        organization_id=org.id,
        seq=_SEQ[0],
        timestamp=ts,
        agent_id=agent_id,
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
    session.add(ev)
    session.commit()
    return ev


def _findings(session: Session, org: Organization) -> list[Finding]:
    return list(
        session.query(Finding).filter(Finding.organization_id == org.id).all()
    )


def test_prompt_injection_finding(session: Session, org: Organization) -> None:
    _audit(session, org, decision="deny", matched_policy_id="pi-deny-instruction-override")
    run_detections(session, org_id=org.id)
    session.commit()
    fs = [f for f in _findings(session, org) if f.rule_id == "prompt-injection-detected"]
    assert len(fs) == 1
    assert fs[0].category == FindingCategory.PROMPT_INJECTION
    assert fs[0].severity == FindingSeverity.HIGH
    assert fs[0].owasp_llm == "LLM01"


def test_repeated_denials_finding(session: Session, org: Organization) -> None:
    for _ in range(5):
        _audit(session, org, decision="deny", matched_policy_id="abuse-deny-x")
    run_detections(session, org_id=org.id)
    session.commit()
    fs = [f for f in _findings(session, org) if f.rule_id == "repeated-denials"]
    assert len(fs) == 1
    assert fs[0].count == 5


def test_repeated_denials_below_threshold_no_finding(
    session: Session, org: Organization
) -> None:
    for _ in range(3):
        _audit(session, org, decision="deny")
    run_detections(session, org_id=org.id)
    session.commit()
    assert not [f for f in _findings(session, org) if f.rule_id == "repeated-denials"]


def test_injection_exfil_killchain_finding(
    session: Session, org: Organization
) -> None:
    _audit(session, org, decision="deny", matched_policy_id="pi-deny-instruction-override",
           session_id="s-kc")
    _audit(session, org, decision="deny",
           matched_policy_id="abuse-deny-known-exfil-webhooks", session_id="s-kc")
    run_detections(session, org_id=org.id)
    session.commit()
    fs = [f for f in _findings(session, org) if f.rule_id == "injection-exfil-killchain"]
    assert len(fs) == 1
    assert fs[0].severity == FindingSeverity.CRITICAL
    assert fs[0].category == FindingCategory.DATA_EXFIL


def test_findings_dedupe_across_runs(session: Session, org: Organization) -> None:
    for _ in range(5):
        _audit(session, org, decision="deny", matched_policy_id="abuse-deny-x")
    r1 = run_detections(session, org_id=org.id)
    session.commit()
    r2 = run_detections(session, org_id=org.id)
    session.commit()
    assert r1["created"] >= 1
    # Second run updates the live finding rather than creating a duplicate.
    assert r2["created"] == 0 and r2["updated"] >= 1
    assert len([f for f in _findings(session, org) if f.rule_id == "repeated-denials"]) == 1


def test_new_tool_anomaly(session: Session, org: Organization) -> None:
    # Baseline usage (2 days ago) of one tool; a brand-new tool now is anomalous.
    _audit(session, org, tool_name="fs.read", decision="allow",
           minutes_ago=60 * 24 * 2)
    _audit(session, org, tool_name="crypto.transfer", decision="allow", minutes_ago=1)
    run_detections(session, org_id=org.id)
    session.commit()
    anomalies = [f for f in _findings(session, org) if f.rule_id == "new-tool-anomaly"]
    tools = {f.evidence.get("tool_name") for f in anomalies}
    assert "crypto.transfer" in tools
    assert "fs.read" not in tools  # in baseline, not anomalous
