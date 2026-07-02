"""Approval inbox: list pending, resolve."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.deps import get_owned
from app.models import ApprovalRequest, ApprovalStatus, Organization
from app.schemas import ApprovalCreateIn, ApprovalRequestOut, ApprovalResolveIn
from app.settings import Settings, get_settings
from app.workers.tasks import notify_approval_task

router = APIRouter(tags=["approvals"])

# Reject Slack callbacks whose signed timestamp is older than this (replay
# protection), per Slack's guidance.
_SLACK_MAX_SKEW_SECONDS = 60 * 5


def _apply_resolution(
    approval: ApprovalRequest, *, approved: bool, resolved_by: str | None
) -> None:
    approval.status = (
        ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
    )
    approval.resolved_at = datetime.now(UTC)
    approval.resolved_by = resolved_by


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
    # Commit so the worker (which opens its own session) sees the row, then
    # enqueue the notification. Eager mode (tests + dev) runs it inline.
    session.commit()
    notify_approval_task.delay(approval.id)
    session.refresh(approval)
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
    _apply_resolution(approval, approved=body.approved, resolved_by=body.resolved_by)
    session.flush()
    return approval


def _verify_slack_signature(
    settings: Settings,
    raw_body: bytes,
    signature: str | None,
    timestamp: str | None,
) -> None:
    """Verify Slack's request signature (v0 HMAC-SHA256 over the raw body).

    Raises 503 if no secret is configured, 401 on a missing/stale/invalid
    signature.
    """
    if not settings.slack_signing_secret:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Slack signing secret not configured",
        )
    if not signature or not timestamp:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="missing Slack signature"
        )
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="invalid Slack timestamp"
        ) from exc
    if abs(time.time() - ts) > _SLACK_MAX_SKEW_SECONDS:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="stale Slack request"
        )
    base = b"v0:" + timestamp.encode() + b":" + raw_body
    digest = hmac.new(
        settings.slack_signing_secret.encode(), base, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(f"v0={digest}", signature):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="bad Slack signature"
        )


@router.post("/approvals/slack/actions")
async def slack_actions(
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    x_slack_signature: Annotated[str | None, Header()] = None,
    x_slack_request_timestamp: Annotated[str | None, Header()] = None,
) -> dict[str, str]:
    """Resolve an approval from a Slack Approve/Deny button.

    Authenticated by Slack's request signature (not an org API key), so the
    approval is located by its unguessable id; the signed payload proves the
    click came from our Slack app. Returns a message body Slack renders in
    place of the original buttons.
    """
    raw_body = await request.body()
    _verify_slack_signature(
        settings, raw_body, x_slack_signature, x_slack_request_timestamp
    )

    form = parse_qs(raw_body.decode())
    payload_values = form.get("payload")
    if not payload_values:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="missing interactive payload"
        )
    try:
        payload = json.loads(payload_values[0])
        action_value = payload["actions"][0]["value"]
        verb, approval_id = action_value.split(":", 1)
    except (json.JSONDecodeError, KeyError, IndexError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="malformed interactive payload"
        ) from exc
    if verb not in ("approve", "deny"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail=f"unknown action {verb!r}"
        )

    user = payload.get("user") or {}
    resolved_by = f"slack:{user.get('username') or user.get('id') or 'unknown'}"

    approval = session.get(ApprovalRequest, approval_id)
    if approval is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail="approval not found"
        )
    if approval.status is not ApprovalStatus.PENDING:
        # Already resolved (double click, or resolved in the dashboard). Not an
        # error — tell Slack what happened so the user sees a sensible message.
        return {"text": f"Already {approval.status.value}."}

    _apply_resolution(approval, approved=verb == "approve", resolved_by=resolved_by)
    session.flush()
    outcome = "approved" if verb == "approve" else "denied"
    return {"text": f"`{approval.tool_name}` {outcome} by {resolved_by}."}
