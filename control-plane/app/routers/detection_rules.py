"""Detection-as-code: author/manage custom detection rules."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.deps import get_owned
from app.models import DetectionRule, Organization
from app.schemas import DetectionRuleIn, DetectionRuleOut

router = APIRouter(tags=["detection-rules"])


@router.post(
    "/detection-rules",
    response_model=DetectionRuleOut,
    status_code=status.HTTP_201_CREATED,
)
def create_rule(
    body: DetectionRuleIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> DetectionRule:
    rule = DetectionRule(
        organization_id=org.id,
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        severity=body.severity,
        category=body.category,
        spec=body.spec.model_dump(),
        atlas_technique=body.atlas_technique,
        owasp_llm=body.owasp_llm,
    )
    session.add(rule)
    try:
        with session.begin_nested():
            session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"a detection rule named {body.name!r} already exists",
        ) from exc
    return rule


@router.get("/detection-rules", response_model=list[DetectionRuleOut])
def list_rules(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[DetectionRule]:
    return list(
        session.execute(
            select(DetectionRule)
            .where(DetectionRule.organization_id == org.id)
            .order_by(DetectionRule.created_at.desc())
        ).scalars()
    )


@router.get("/detection-rules/{rule_id}", response_model=DetectionRuleOut)
def get_rule(
    rule_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> DetectionRule:
    return get_owned(
        session, DetectionRule, rule_id, org, detail="detection rule not found"
    )


@router.put("/detection-rules/{rule_id}", response_model=DetectionRuleOut)
def update_rule(
    rule_id: str,
    body: DetectionRuleIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> DetectionRule:
    rule = get_owned(
        session, DetectionRule, rule_id, org, detail="detection rule not found"
    )
    rule.name = body.name
    rule.description = body.description
    rule.enabled = body.enabled
    rule.severity = body.severity
    rule.category = body.category
    rule.spec = body.spec.model_dump()
    rule.atlas_technique = body.atlas_technique
    rule.owasp_llm = body.owasp_llm
    session.flush()
    return rule


@router.delete(
    "/detection-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_rule(
    rule_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> None:
    rule = get_owned(
        session, DetectionRule, rule_id, org, detail="detection rule not found"
    )
    session.delete(rule)
    session.flush()
