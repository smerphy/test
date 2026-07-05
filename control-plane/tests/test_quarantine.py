from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Organization,
)
from app.services.quarantine import (
    auto_quarantine_for_finding,
    create_quarantine,
    match_quarantine,
)


def test_create_and_check_agent_quarantine(client: TestClient) -> None:
    r = client.post(
        "/quarantines", json={"agent_id": "rogue-1", "reason": "compromised"}
    )
    assert r.status_code == 201
    assert r.json()["active"] is True

    hit = client.get("/quarantines/check?agent_id=rogue-1").json()
    assert hit["quarantined"] is True and hit["reason"] == "compromised"
    miss = client.get("/quarantines/check?agent_id=other").json()
    assert miss["quarantined"] is False


def test_create_requires_an_entity(client: TestClient) -> None:
    r = client.post("/quarantines", json={"reason": "no entity"})
    assert r.status_code == 422


def test_active_list_and_lift(client: TestClient) -> None:
    qid = client.post(
        "/quarantines", json={"session_id": "s-9", "reason": "probing"}
    ).json()["id"]
    assert len(client.get("/quarantines/active").json()) == 1

    client.post(f"/quarantines/{qid}/lift?lifted_by=analyst")
    assert client.get("/quarantines/active").json() == []
    assert client.get("/quarantines/check?session_id=s-9").json()["quarantined"] is False


def test_expired_quarantine_not_active(
    session: Session, org: Organization
) -> None:
    create_quarantine(
        session,
        org_id=org.id,
        agent_id="a",
        session_id=None,
        reason="temp",
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    session.commit()
    assert match_quarantine(session, org.id, agent_id="a", session_id=None) is None


def test_quarantine_is_org_scoped(
    client: TestClient, session: Session, org: Organization
) -> None:
    other = Organization(name="Other", slug="other")
    session.add(other)
    session.commit()
    q = create_quarantine(
        session, org_id=other.id, agent_id="x", session_id=None, reason="r"
    )
    session.commit()
    # acme cannot lift the rival org's quarantine.
    assert client.post(f"/quarantines/{q.id}/lift").status_code == 404


def _critical_finding(session: Session, org: Organization) -> Finding:
    now = datetime.now(UTC)
    f = Finding(
        organization_id=org.id,
        rule_id="injection-exfil-killchain",
        title="kill chain",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.DATA_EXFIL,
        status=FindingStatus.OPEN,
        agent_id="agent-x",
        session_id="sess-x",
        dedup_key="k",
        count=1,
        first_seen=now,
        last_seen=now,
        evidence={},
    )
    session.add(f)
    session.commit()
    return f


def test_auto_response_disabled_by_default(
    session: Session, org: Organization
) -> None:
    f = _critical_finding(session, org)
    assert auto_quarantine_for_finding(session, org, f) is None


def test_auto_response_quarantines_critical(
    session: Session, org: Organization
) -> None:
    org.auto_quarantine = True
    f = _critical_finding(session, org)
    q = auto_quarantine_for_finding(session, org, f)
    session.commit()
    assert q is not None
    assert q.source.value == "auto"
    assert q.finding_id == f.id
    # The finding's entity is now isolated.
    assert (
        match_quarantine(session, org.id, agent_id="agent-x", session_id="sess-x")
        is not None
    )
    # Idempotent: a second call doesn't double-quarantine.
    assert auto_quarantine_for_finding(session, org, f) is None
