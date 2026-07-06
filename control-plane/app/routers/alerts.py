"""Alert rules CRUD + manual evaluation trigger + alert history."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import (
    AlertChannel,
    AlertEvent,
    AlertRule,
    AlertState,
    Organization,
    Role,
)
from app.schemas import (
    AlertAcknowledgeIn,
    AlertEventOut,
    AlertRuleIn,
    AlertRuleOut,
)
from app.services.alerts import evaluate_rule
from app.services.egress import EgressBlocked, assert_safe_webhook_url

router = APIRouter(tags=["alerts"])


@router.post(
    "/alerts/rules",
    response_model=AlertRuleOut,
    status_code=status.HTTP_201_CREATED,
)
def create_rule(
    body: AlertRuleIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> AlertRule:
    # SLACK/WEBHOOK targets are URLs the control plane POSTs to; reject
    # internal addresses up front (SSRF guard). PagerDuty target is a routing
    # key, not a URL.
    if body.channel in (AlertChannel.SLACK, AlertChannel.WEBHOOK):
        try:
            assert_safe_webhook_url(body.target)
        except EgressBlocked as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"target rejected: {exc}",
            ) from exc
    rule = AlertRule(
        organization_id=org.id,
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        metric=body.metric,
        aggregation=body.aggregation,
        window_minutes=body.window_minutes,
        threshold=body.threshold,
        comparison=body.comparison,
        group_by=body.group_by,
        filter_model=body.filter_model,
        filter_agent_id=body.filter_agent_id,
        severity=body.severity,
        channel=body.channel,
        target=body.target,
        cooldown_minutes=body.cooldown_minutes,
    )
    session.add(rule)
    session.flush()
    return rule


@router.get("/alerts/rules", response_model=list[AlertRuleOut])
def list_rules(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[AlertRule]:
    stmt = (
        select(AlertRule)
        .where(AlertRule.organization_id == org.id)
        .order_by(AlertRule.created_at.desc())
    )
    return list(session.execute(stmt).scalars().all())


@router.get("/alerts/rules/{rule_id}", response_model=AlertRuleOut)
def get_rule(
    rule_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> AlertRule:
    return get_owned(session, AlertRule, rule_id, org, detail="rule not found")


@router.post("/alerts/rules/{rule_id}/evaluate", response_model=list[AlertEventOut])
def evaluate_now(
    rule_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> list[AlertEvent]:
    rule = get_owned(session, AlertRule, rule_id, org, detail="rule not found")
    return evaluate_rule(session, rule)


@router.post(
    "/alerts/events/{event_id}/acknowledge", response_model=AlertEventOut
)
def acknowledge_event(
    event_id: str,
    body: AlertAcknowledgeIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> AlertEvent:
    event = get_owned(
        session, AlertEvent, event_id, org, detail="alert event not found"
    )
    if event.state is AlertState.RESOLVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="already resolved; nothing to acknowledge",
        )
    event.state = AlertState.ACKNOWLEDGED
    event.acknowledged_at = datetime.now(UTC)
    event.acknowledged_by = body.acknowledged_by
    if body.note:
        # Append note to the payload for the audit trail.
        existing = dict(event.payload or {})
        existing.setdefault("notes", []).append(
            {"at": event.acknowledged_at.isoformat(), "by": body.acknowledged_by, "text": body.note}
        )
        event.payload = existing
    session.flush()
    return event


@router.get("/alerts/events", response_model=list[AlertEventOut])
def list_events(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    rule_id: str | None = None,
    state: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AlertEvent]:
    stmt = (
        select(AlertEvent)
        .where(AlertEvent.organization_id == org.id)
        .order_by(AlertEvent.fired_at.desc())
        .limit(limit)
    )
    if rule_id:
        stmt = stmt.where(AlertEvent.rule_id == rule_id)
    if state:
        stmt = stmt.where(AlertEvent.state == state)
    return list(session.execute(stmt).scalars().all())
