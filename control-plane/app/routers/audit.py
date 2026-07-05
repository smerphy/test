"""Audit event ingestion + search."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from annotated_types import Len
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.models import AuditEvent, Organization, Role
from app.schemas import AuditEventIn, AuditEventOut, AuditIngestResult
from app.services.access_log import access_log
from app.services.audit_ingest import ingest_event
from app.services.event_store import archive_events
from app.services.ratelimit import rate_limit

router = APIRouter(tags=["audit"])


@router.post(
    "/audit/events",
    response_model=AuditIngestResult,
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_events(
    events: Annotated[list[AuditEventIn], Len(max_length=1000)],
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
    _rl: None = Depends(rate_limit("ingest")),
) -> AuditIngestResult:
    accepted = 0
    errors: list[str] = []
    archived: list[dict[str, Any]] = []
    for raw in events:
        try:
            ingest_event(session, org_id=org.id, event=raw)
            accepted += 1
            archived.append(raw.model_dump(mode="json"))
        except ValueError as exc:
            errors.append(f"seq={raw.seq}: {exc}")
    # Stream accepted events to the cold tier (no-op unless configured).
    archive_events("audit", org.id, archived)
    return AuditIngestResult(
        accepted=accepted, rejected=len(events) - accepted, errors=errors
    )


@router.get("/audit/events", response_model=list[AuditEventOut])
def search_events(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _al: None = Depends(access_log("audit")),
    agent_id: str | None = None,
    tool_name: str | None = None,
    decision: str | None = None,
    session_id: str | None = None,
    matched_policy_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditEvent]:
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.organization_id == org.id)
        .order_by(AuditEvent.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )
    if agent_id:
        stmt = stmt.where(AuditEvent.agent_id == agent_id)
    if tool_name:
        stmt = stmt.where(AuditEvent.tool_name == tool_name)
    if decision:
        stmt = stmt.where(AuditEvent.decision == decision)
    if session_id:
        stmt = stmt.where(AuditEvent.session_id == session_id)
    if matched_policy_id:
        stmt = stmt.where(AuditEvent.matched_policy_id == matched_policy_id)
    if since:
        stmt = stmt.where(AuditEvent.timestamp >= since)
    if until:
        stmt = stmt.where(AuditEvent.timestamp <= until)
    return list(session.execute(stmt).scalars().all())
