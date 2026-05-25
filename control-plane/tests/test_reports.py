from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditEvent, Organization


def _seed_events(session: Session, org: Organization, base: datetime) -> None:
    chain_prev = "0" * 64
    for i, decision in enumerate(["allow", "allow", "deny", "require_approval"]):
        # Hash needs to be unique per event (uq_audit_org_hash).
        # Tests skip chain re-verification — we just want distinct rows.
        synthetic_hash = f"{i:064x}"
        ev = AuditEvent(
            organization_id=org.id,
            seq=i,
            timestamp=base + timedelta(minutes=i),
            agent_id="a",
            session_id="s",
            tool_name="http.get",
            tool_arguments={},
            decision=decision,
            reason="test",
            matched_policy_id=f"p-{decision}",
            context={},
            evaluator_version="0.1.0",
            prev_hash=chain_prev,
            hash=synthetic_hash,
        )
        session.add(ev)
        chain_prev = synthetic_hash
    session.commit()


def test_generate_compliance_report(
    client: TestClient, session: Session, org: Organization
) -> None:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    _seed_events(session, org, base)

    r = client.post(
        "/reports/compliance",
        json={
            "framework": "nist_ai_rmf",
            "period_start": base.isoformat(),
            "period_end": (base + timedelta(hours=1)).isoformat(),
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "complete"
    summary = body["summary"]
    assert summary["framework"] == "nist_ai_rmf"
    assert summary["total_evaluations"] == 4
    assert summary["decision_counts"]["allow"] == 2
    assert summary["decision_counts"]["deny"] == 1
    assert summary["deny_rate"] == 0.25
    assert summary["approval_rate"] == 0.25
    assert "GOVERN-1.1" in summary["controls"]


def test_invalid_period_rejected(client: TestClient) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    r = client.post(
        "/reports/compliance",
        json={
            "framework": "nist_ai_rmf",
            "period_start": now.isoformat(),
            "period_end": (now - timedelta(hours=1)).isoformat(),
        },
    )
    assert r.status_code == 422


def test_unknown_framework_rejected(client: TestClient) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    r = client.post(
        "/reports/compliance",
        json={
            "framework": "bogus",
            "period_start": now.isoformat(),
            "period_end": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert r.status_code == 422


def test_list_and_get_reports(
    client: TestClient, session: Session, org: Organization
) -> None:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    _seed_events(session, org, base)

    rid = client.post(
        "/reports/compliance",
        json={
            "framework": "iso_42001",
            "period_start": base.isoformat(),
            "period_end": (base + timedelta(hours=1)).isoformat(),
        },
    ).json()["id"]

    listing = client.get("/reports/compliance").json()
    assert any(r["id"] == rid for r in listing)

    r = client.get(f"/reports/compliance/{rid}")
    assert r.status_code == 200
    assert r.json()["framework"] == "iso_42001"
