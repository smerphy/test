"""Security findings: list, inspect, triage, and run detections on demand.

Findings are produced by the detection engine (scheduled via Celery beat);
these endpoints are the analyst surface — the SIEM/EDR console's backend.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Organization,
    Role,
)
from app.schemas import FindingOut, FindingUpdateIn
from app.services.detections import run_detections

router = APIRouter(tags=["findings"])

_TERMINAL = (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE)


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    status_filter: Annotated[FindingStatus | None, Query(alias="status")] = None,
    severity: FindingSeverity | None = None,
    category: FindingCategory | None = None,
    agent_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Finding]:
    stmt = (
        select(Finding)
        .where(Finding.organization_id == org.id)
        .order_by(Finding.last_seen.desc())
        .limit(limit)
        .offset(offset)
    )
    if status_filter:
        stmt = stmt.where(Finding.status == status_filter)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if category:
        stmt = stmt.where(Finding.category == category)
    if agent_id:
        stmt = stmt.where(Finding.agent_id == agent_id)
    return list(session.execute(stmt).scalars().all())


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> Finding:
    return get_owned(session, Finding, finding_id, org, detail="finding not found")


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: str,
    body: FindingUpdateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> Finding:
    """Triage a finding: change status, assign, or annotate."""
    finding = get_owned(
        session, Finding, finding_id, org, detail="finding not found"
    )
    fields = body.model_dump(exclude_unset=True)
    if "assignee" in fields:
        finding.assignee = fields["assignee"]
    if "note" in fields:
        finding.note = fields["note"]
    if "status" in fields and fields["status"] is not None:
        new_status = fields["status"]
        finding.status = new_status
        if new_status in _TERMINAL:
            finding.resolved_at = datetime.now(UTC)
            finding.resolved_by = fields.get("resolved_by") or finding.resolved_by
        else:
            finding.resolved_at = None
            finding.resolved_by = None
    session.flush()
    return finding


@router.post("/findings/run", response_model=dict[str, Any])
def run_now(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
    window_minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
) -> dict[str, Any]:
    """Run the detection engine for this org immediately (returns created/updated)."""
    return run_detections(session, org_id=org.id, window_minutes=window_minutes)
