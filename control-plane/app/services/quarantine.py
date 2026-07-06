"""Quarantine service: query/apply the EDR kill-switch and auto-response."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    FindingSeverity,
    Organization,
    Quarantine,
    QuarantineSource,
)


def _is_expired(q: Quarantine, now: datetime) -> bool:
    if q.expires_at is None:
        return False
    exp = q.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=UTC)
    return now > exp


def active_quarantines(
    session: Session, org_id: str, *, now: datetime | None = None
) -> list[Quarantine]:
    now = now or datetime.now(UTC)
    rows = list(
        session.execute(
            select(Quarantine).where(
                Quarantine.organization_id == org_id,
                Quarantine.active.is_(True),
            )
        ).scalars()
    )
    return [q for q in rows if not _is_expired(q, now)]


def match_quarantine(
    session: Session,
    org_id: str,
    *,
    agent_id: str | None,
    session_id: str | None,
    now: datetime | None = None,
) -> Quarantine | None:
    """Return an active quarantine isolating this (agent, session), or None."""
    now = now or datetime.now(UTC)
    conds = []
    if agent_id is not None:
        conds.append(Quarantine.agent_id == agent_id)
    if session_id is not None:
        conds.append(Quarantine.session_id == session_id)
    if not conds:
        return None
    rows = list(
        session.execute(
            select(Quarantine).where(
                Quarantine.organization_id == org_id,
                Quarantine.active.is_(True),
                or_(*conds),
            )
        ).scalars()
    )
    for q in rows:
        if not _is_expired(q, now):
            return q
    return None


def create_quarantine(
    session: Session,
    *,
    org_id: str,
    agent_id: str | None,
    session_id: str | None,
    reason: str,
    source: QuarantineSource = QuarantineSource.MANUAL,
    finding_id: str | None = None,
    created_by: str | None = None,
    expires_at: datetime | None = None,
) -> Quarantine:
    q = Quarantine(
        organization_id=org_id,
        agent_id=agent_id,
        session_id=session_id,
        reason=reason,
        source=source,
        finding_id=finding_id,
        created_by=created_by,
        expires_at=expires_at,
        active=True,
    )
    session.add(q)
    session.flush()
    return q


def lift_quarantine(
    q: Quarantine, *, lifted_by: str | None = None, now: datetime | None = None
) -> None:
    q.active = False
    q.lifted_at = now or datetime.now(UTC)
    q.lifted_by = lifted_by


def auto_quarantine_for_finding(
    session: Session, org: Organization, finding: Finding
) -> Quarantine | None:
    """If auto-response is enabled and the finding is CRITICAL, isolate its
    entity (idempotently). Returns the created quarantine, or None."""
    if not org.auto_quarantine:
        return None
    if finding.severity != FindingSeverity.CRITICAL:
        return None
    if finding.agent_id is None and finding.session_id is None:
        return None
    # Don't double-quarantine an entity that's already isolated.
    if (
        match_quarantine(
            session,
            org.id,
            agent_id=finding.agent_id,
            session_id=finding.session_id,
        )
        is not None
    ):
        return None
    return create_quarantine(
        session,
        org_id=org.id,
        agent_id=finding.agent_id,
        session_id=finding.session_id,
        reason=f"auto-response to finding: {finding.title}",
        source=QuarantineSource.AUTO,
        finding_id=finding.id,
    )


__all__ = [
    "active_quarantines",
    "auto_quarantine_for_finding",
    "create_quarantine",
    "lift_quarantine",
    "match_quarantine",
]
