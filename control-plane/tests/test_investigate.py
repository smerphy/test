from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    ApprovalRequest,
    AuditEvent,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Organization,
)
from app.services.quarantine import create_quarantine

_SEQ = [0]


def _audit(
    session: Session,
    org: Organization,
    *,
    decision: str,
    session_id: str = "s1",
    tool_name: str = "http.get",
    minutes_ago: float = 1.0,
) -> None:
    _SEQ[0] += 1
    session.add(
        AuditEvent(
            organization_id=org.id,
            seq=_SEQ[0],
            timestamp=datetime.now(UTC) - timedelta(minutes=minutes_ago),
            agent_id="agent-1",
            session_id=session_id,
            tool_name=tool_name,
            tool_arguments={},
            decision=decision,
            reason="r",
            context={},
            evaluator_version="0.1.0",
            prev_hash="0" * 64,
            hash=f"{_SEQ[0]:064d}",
        )
    )
    session.commit()


def _finding(session: Session, org: Organization, *, session_id: str = "s1") -> Finding:
    now = datetime.now(UTC)
    f = Finding(
        organization_id=org.id,
        rule_id="prompt-injection-detected",
        title="pi",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.PROMPT_INJECTION,
        status=FindingStatus.OPEN,
        agent_id="agent-1",
        session_id=session_id,
        dedup_key="k",
        count=1,
        first_seen=now,
        last_seen=now,
        evidence={},
    )
    session.add(f)
    session.commit()
    return f


def test_overview(client: TestClient, session: Session, org: Organization) -> None:
    _audit(session, org, decision="allow")
    _audit(session, org, decision="deny")
    _finding(session, org)
    session.add(
        ApprovalRequest(
            organization_id=org.id, agent_id="a", session_id="s1",
            tool_name="t", tool_arguments={}, policy_id=None, reason="r",
        )
    )
    session.commit()

    body = client.get("/overview").json()
    assert body["findings"]["open_total"] == 1
    assert body["findings"]["critical_open"] == 1
    assert body["approvals"]["pending"] == 1
    assert body["activity_24h"]["total"] == 2
    assert body["activity_24h"]["decisions"]["deny"] == 1


def test_session_timeline_is_chronological_and_merged(
    client: TestClient, session: Session, org: Organization
) -> None:
    _audit(session, org, decision="deny", session_id="s-tl", minutes_ago=10)
    _audit(session, org, decision="allow", session_id="s-tl", minutes_ago=5)
    _finding(session, org, session_id="s-tl")
    create_quarantine(
        session, org_id=org.id, agent_id=None, session_id="s-tl", reason="isolated"
    )
    session.commit()

    entries = client.get("/timeline/session/s-tl").json()
    kinds = [e["kind"] for e in entries]
    assert "decision" in kinds and "finding" in kinds and "quarantine" in kinds
    # Sorted ascending by time.
    times = [e["at"] for e in entries]
    assert times == sorted(times)


def test_overview_is_org_scoped(
    client: TestClient, session: Session, org: Organization
) -> None:
    other = Organization(name="Other", slug="other")
    session.add(other)
    session.commit()
    _finding(session, other)  # belongs to the rival org
    # acme sees none of the rival's findings.
    assert client.get("/overview").json()["findings"]["open_total"] == 0
