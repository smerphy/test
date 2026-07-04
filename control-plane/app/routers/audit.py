"""Audit event ingestion + search."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from annotated_types import Len
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.models import AuditEvent, Organization
from app.schemas import AuditEventIn, AuditEventOut, AuditIngestResult
from app.services.audit_ingest import ingest_event

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
) -> AuditIngestResult:
    accepted = 0
    errors: list[str] = []
    for raw in events:
        try:
            ingest_event(session, org_id=org.id, event=raw)
            accepted += 1
        except ValueError as exc:
            errors.append(f"seq={raw.seq}: {exc}")
    return AuditIngestResult(
        accepted=accepted, rejected=len(events) - accepted, errors=errors
    )


@router.get("/audit/events", response_model=list[AuditEventOut])
def search_events(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
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
