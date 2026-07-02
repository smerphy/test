from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditEvent, Organization


def _seed(session: Session, org: Organization, base: datetime) -> None:
    for i, decision in enumerate(["allow", "deny", "allow", "transform"]):
        session.add(
            AuditEvent(
                organization_id=org.id,
                seq=i,
                timestamp=base + timedelta(minutes=i),
                agent_id="a",
                session_id="s",
                tool_name="http.get",
                tool_arguments={},
                decision=decision,
                reason="x",
                matched_policy_id=f"p-{decision}",
                context={},
                evaluator_version="0.1.0",
                prev_hash="0" * 64,
                hash=f"{i:064x}",  # unique per row
            )
        )
    session.commit()


def test_pdf_download_for_complete_report(
    client: TestClient, session: Session, org: Organization
) -> None:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    _seed(session, org, base)
    rid = client.post(
        "/reports/compliance",
        json={
            "framework": "nist_ai_rmf",
            "period_start": base.isoformat(),
            "period_end": (base + timedelta(hours=1)).isoformat(),
        },
    ).json()["id"]

    r = client.get(f"/reports/compliance/{rid}/pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    # Real PDF starts with %PDF-
    assert r.content[:5] == b"%PDF-"
    assert "attachment" in r.headers["content-disposition"]
    # File size is reasonable (>1 KB but small).
    assert 1_000 < len(r.content) < 100_000


def test_pdf_unknown_report_404(client: TestClient) -> None:
    r = client.get("/reports/compliance/missing/pdf")
    assert r.status_code == 404
