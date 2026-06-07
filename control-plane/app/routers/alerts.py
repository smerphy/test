"""Alert rules CRUD + manual evaluation trigger + alert history."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.models import AlertEvent, AlertRule, Organization
from app.schemas import AlertEventOut, AlertRuleIn, AlertRuleOut
from app.services.alerts import evaluate_rule

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
) -> AlertRule:
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
    rule = session.get(AlertRule, rule_id)
    if rule is None or rule.organization_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="rule not found")
    return rule


@router.post("/alerts/rules/{rule_id}/evaluate", response_model=list[AlertEventOut])
def evaluate_now(
    rule_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[AlertEvent]:
    rule = session.get(AlertRule, rule_id)
    if rule is None or rule.organization_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="rule not found")
    return evaluate_rule(session, rule)


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
