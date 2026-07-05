"""Investigation & SOC-overview read models.

`security_overview` powers a SOC dashboard (posture at a glance);
`session_timeline` reconstructs everything that happened in one agent
session (audit decisions, findings, approvals, quarantines) in
chronological order for forensics.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    ApprovalRequest,
    ApprovalStatus,
    AuditEvent,
    Finding,
    FindingSeverity,
    FindingStatus,
    Quarantine,
)
from app.services.quarantine import active_quarantines


def _strip(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def security_overview(
    session: Session, org_id: str, *, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    since_24h = _strip(now - timedelta(hours=24))

    open_statuses = (FindingStatus.OPEN, FindingStatus.TRIAGING)
    by_severity: dict[str, int] = {
        str(row[0]): int(row[1])
        for row in session.execute(
            select(Finding.severity, func.count())
            .where(
                Finding.organization_id == org_id,
                Finding.status.in_(open_statuses),
            )
            .group_by(Finding.severity)
        ).all()
    }
    by_category: dict[str, int] = {
        str(row[0]): int(row[1])
        for row in session.execute(
            select(Finding.category, func.count())
            .where(
                Finding.organization_id == org_id,
                Finding.status.in_(open_statuses),
            )
            .group_by(Finding.category)
        ).all()
    }
    open_total = sum(by_severity.values())

    decisions_24h: dict[str, int] = {
        str(row[0]): int(row[1])
        for row in session.execute(
            select(AuditEvent.decision, func.count())
            .where(
                AuditEvent.organization_id == org_id,
                AuditEvent.timestamp >= since_24h,
            )
            .group_by(AuditEvent.decision)
        ).all()
    }

    pending_approvals = session.execute(
        select(func.count())
        .select_from(ApprovalRequest)
        .where(
            ApprovalRequest.organization_id == org_id,
            ApprovalRequest.status == ApprovalStatus.PENDING,
        )
    ).scalar_one()

    return {
        "findings": {
            "open_total": open_total,
            "critical_open": by_severity.get(str(FindingSeverity.CRITICAL), 0),
            "by_severity": by_severity,
            "by_category": by_category,
        },
        "quarantines": {"active": len(active_quarantines(session, org_id, now=now))},
        "approvals": {"pending": int(pending_approvals)},
        "activity_24h": {
            "decisions": decisions_24h,
            "total": sum(decisions_24h.values()),
        },
    }


def session_timeline(
    session: Session, org_id: str, session_id: str, *, limit: int = 500
) -> list[dict[str, Any]]:
    """Chronological merge of everything recorded for one session."""
    entries: list[dict[str, Any]] = []

    for ev in session.execute(
        select(AuditEvent)
        .where(
            AuditEvent.organization_id == org_id,
            AuditEvent.session_id == session_id,
        )
        .order_by(AuditEvent.timestamp.asc())
        .limit(limit)
    ).scalars():
        entries.append(
            {
                "at": ev.timestamp,
                "kind": "decision",
                "title": f"{ev.decision} {ev.tool_name}",
                "detail": {
                    "agent_id": ev.agent_id,
                    "decision": ev.decision,
                    "matched_policy_id": ev.matched_policy_id,
                    "reason": ev.reason,
                },
            }
        )

    for f in session.execute(
        select(Finding).where(
            Finding.organization_id == org_id, Finding.session_id == session_id
        )
    ).scalars():
        entries.append(
            {
                "at": f.first_seen,
                "kind": "finding",
                "title": f.title,
                "detail": {
                    "id": f.id,
                    "severity": str(f.severity),
                    "category": str(f.category),
                    "status": str(f.status),
                },
            }
        )

    for a in session.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.organization_id == org_id,
            ApprovalRequest.session_id == session_id,
        )
    ).scalars():
        entries.append(
            {
                "at": a.created_at,
                "kind": "approval",
                "title": f"approval {a.status} for {a.tool_name}",
                "detail": {"id": a.id, "status": str(a.status), "reason": a.reason},
            }
        )

    for q in session.execute(
        select(Quarantine).where(
            Quarantine.organization_id == org_id,
            Quarantine.session_id == session_id,
        )
    ).scalars():
        entries.append(
            {
                "at": q.created_at,
                "kind": "quarantine",
                "title": f"quarantine ({q.source})",
                "detail": {"id": q.id, "reason": q.reason, "active": q.active},
            }
        )

    entries.sort(key=lambda e: _strip(e["at"]))
    return entries


__all__ = ["security_overview", "session_timeline"]
