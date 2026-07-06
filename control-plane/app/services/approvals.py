"""Approval lifecycle helpers (expiry sweep)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ApprovalRequest, ApprovalStatus


def expire_stale_approvals(
    session: Session, *, now: datetime | None = None
) -> int:
    """Mark every PENDING approval whose `expires_at` has passed as EXPIRED.

    Returns the number expired. A resolver (dashboard, Slack, SDK poll) that
    sees EXPIRED treats it as a denial, so a crashed agent's request doesn't
    sit pending forever and the SDK's poll terminates deterministically.
    """
    now = now or datetime.now(UTC)
    stale = list(
        session.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.status == ApprovalStatus.PENDING,
                ApprovalRequest.expires_at.is_not(None),
                ApprovalRequest.expires_at < now,
            )
        ).scalars()
    )
    for approval in stale:
        approval.status = ApprovalStatus.EXPIRED
        approval.resolved_at = now
    session.flush()
    return len(stale)


__all__ = ["expire_stale_approvals"]
