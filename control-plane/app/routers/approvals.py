"""Approval inbox: list pending, resolve."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.deps import get_owned
from app.models import ApprovalRequest, ApprovalStatus, Organization
from app.schemas import ApprovalCreateIn, ApprovalRequestOut, ApprovalResolveIn

router = APIRouter(tags=["approvals"])


@router.post(
    "/approvals",
    response_model=ApprovalRequestOut,
    status_code=status.HTTP_201_CREATED,
)
def create_approval(
    body: ApprovalCreateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> ApprovalRequest:
    """Create a pending approval. Called by the SDK when a policy returns
    `require_approval`; the SDK then polls `GET /approvals/{id}` for the
    outcome while a human resolves it in the dashboard."""
    approval = ApprovalRequest(
        organization_id=org.id,
        agent_id=body.agent_id,
        session_id=body.session_id,
        tool_name=body.tool_name,
        tool_arguments=body.tool_arguments,
        policy_id=body.policy_id,
        reason=body.reason,
        status=ApprovalStatus.PENDING,
    )
    session.add(approval)
    session.flush()
    return approval


@router.get("/approvals/{approval_id}", response_model=ApprovalRequestOut)
def get_approval(
    approval_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> ApprovalRequest:
    return get_owned(
        session, ApprovalRequest, approval_id, org, detail="approval not found"
    )


@router.get("/approvals", response_model=list[ApprovalRequestOut])
def list_approvals(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    status_filter: Annotated[
        ApprovalStatus | None, Query(alias="status")
    ] = ApprovalStatus.PENDING,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ApprovalRequest]:
    stmt = (
        select(ApprovalRequest)
        .where(ApprovalRequest.organization_id == org.id)
        .order_by(ApprovalRequest.created_at.desc())
        .limit(limit)
    )
    if status_filter:
        stmt = stmt.where(ApprovalRequest.status == status_filter)
    return list(session.execute(stmt).scalars().all())


@router.post("/approvals/{approval_id}/resolve", response_model=ApprovalRequestOut)
def resolve_approval(
    approval_id: str,
    body: ApprovalResolveIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> ApprovalRequest:
    approval = get_owned(
        session, ApprovalRequest, approval_id, org, detail="approval not found"
    )
    if approval.status is not ApprovalStatus.PENDING:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"approval already {approval.status.value}",
        )
    approval.status = (
        ApprovalStatus.APPROVED if body.approved else ApprovalStatus.DENIED
    )
    approval.resolved_at = datetime.now(UTC)
    approval.resolved_by = body.resolved_by
    session.flush()
    return approval
