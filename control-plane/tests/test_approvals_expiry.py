from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import ApprovalRequest, ApprovalStatus, Organization
from app.services.approvals import expire_stale_approvals


def _pending(
    session: Session,
    org: Organization,
    *,
    expires_at: datetime | None,
    status: ApprovalStatus = ApprovalStatus.PENDING,
) -> ApprovalRequest:
    a = ApprovalRequest(
        organization_id=org.id,
        agent_id="a",
        session_id="s",
        tool_name="t",
        tool_arguments={},
        policy_id=None,
        reason="r",
        status=status,
        expires_at=expires_at,
    )
    session.add(a)
    session.commit()
    return a


def test_expires_stale_pending(session: Session, org: Organization) -> None:
    past = datetime.now(UTC) - timedelta(minutes=5)
    a = _pending(session, org, expires_at=past)
    n = expire_stale_approvals(session)
    session.commit()
    session.refresh(a)
    assert n == 1
    assert a.status is ApprovalStatus.EXPIRED
    assert a.resolved_at is not None


def test_future_expiry_untouched(session: Session, org: Organization) -> None:
    future = datetime.now(UTC) + timedelta(minutes=30)
    a = _pending(session, org, expires_at=future)
    assert expire_stale_approvals(session) == 0
    session.refresh(a)
    assert a.status is ApprovalStatus.PENDING


def test_null_expiry_never_expires(session: Session, org: Organization) -> None:
    a = _pending(session, org, expires_at=None)
    assert expire_stale_approvals(session) == 0
    session.refresh(a)
    assert a.status is ApprovalStatus.PENDING


def test_already_resolved_not_reexpired(
    session: Session, org: Organization
) -> None:
    past = datetime.now(UTC) - timedelta(minutes=5)
    a = _pending(session, org, expires_at=past, status=ApprovalStatus.APPROVED)
    assert expire_stale_approvals(session) == 0
    session.refresh(a)
    assert a.status is ApprovalStatus.APPROVED


def test_create_sets_expires_at(client: TestClient) -> None:
    r = client.post(
        "/approvals",
        json={
            "agent_id": "a",
            "session_id": "s",
            "tool_name": "t",
            "tool_arguments": {},
            "policy_id": None,
            "reason": "r",
        },
    )
    assert r.status_code == 201
    assert r.json()["expires_at"] is not None


def test_expire_task_runs(session: Session, org: Organization) -> None:
    from app.workers.tasks import expire_stale_approvals_task

    _pending(session, org, expires_at=datetime.now(UTC) - timedelta(minutes=1))
    assert expire_stale_approvals_task() == 1
