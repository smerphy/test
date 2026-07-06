from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Organization,
)


def _seed_finding(
    session: Session,
    org: Organization,
    *,
    severity: FindingSeverity = FindingSeverity.HIGH,
    category: FindingCategory = FindingCategory.PROMPT_INJECTION,
    rule_id: str = "prompt-injection-detected",
) -> Finding:
    now = datetime.now(UTC)
    f = Finding(
        organization_id=org.id,
        rule_id=rule_id,
        title="test finding",
        severity=severity,
        category=category,
        status=FindingStatus.OPEN,
        agent_id="agent-1",
        session_id="sess-1",
        dedup_key=f"{rule_id}:sess-1",
        count=1,
        first_seen=now,
        last_seen=now,
        evidence={"event_ids": ["x"]},
        owasp_llm="LLM01",
    )
    session.add(f)
    session.commit()
    return f


def test_list_and_filter_findings(
    client: TestClient, session: Session, org: Organization
) -> None:
    _seed_finding(session, org, severity=FindingSeverity.HIGH)
    _seed_finding(
        session, org, severity=FindingSeverity.LOW,
        category=FindingCategory.ANOMALY, rule_id="new-tool-anomaly",
    )
    assert len(client.get("/findings").json()) == 2
    high = client.get("/findings?severity=high").json()
    assert len(high) == 1 and high[0]["severity"] == "high"
    anom = client.get("/findings?category=anomaly").json()
    assert len(anom) == 1 and anom[0]["category"] == "anomaly"


def test_get_finding(client: TestClient, session: Session, org: Organization) -> None:
    f = _seed_finding(session, org)
    body = client.get(f"/findings/{f.id}").json()
    assert body["id"] == f.id
    assert body["owasp_llm"] == "LLM01"
    assert body["evidence"]["event_ids"] == ["x"]


def test_triage_finding_resolve(
    client: TestClient, session: Session, org: Organization
) -> None:
    f = _seed_finding(session, org)
    r = client.patch(
        f"/findings/{f.id}",
        json={"status": "resolved", "resolved_by": "analyst@acme", "note": "handled"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "resolved"
    assert body["resolved_by"] == "analyst@acme"
    assert body["resolved_at"] is not None
    assert body["note"] == "handled"


def test_triage_assign_without_resolving(
    client: TestClient, session: Session, org: Organization
) -> None:
    f = _seed_finding(session, org)
    r = client.patch(f"/findings/{f.id}", json={"status": "triaging", "assignee": "bob"})
    assert r.json()["status"] == "triaging"
    assert r.json()["assignee"] == "bob"
    assert r.json()["resolved_at"] is None


def test_finding_is_org_scoped(
    client: TestClient, session: Session, org: Organization
) -> None:
    other = Organization(name="Other", slug="other")
    session.add(other)
    session.commit()
    foreign = _seed_finding(session, other)
    # `client` acts as acme; the rival org's finding must not be visible.
    assert client.get(f"/findings/{foreign.id}").status_code == 404


def test_run_detections_endpoint(client: TestClient) -> None:
    r = client.post("/findings/run")
    assert r.status_code == 200
    assert {"created", "updated"} <= set(r.json())
