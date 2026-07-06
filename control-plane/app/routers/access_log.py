"""Access-log viewing (SOC2/ISO evidence of who viewed/exported what)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.models import AccessLog, Organization, Role
from app.schemas import AccessLogOut

router = APIRouter(tags=["access-log"])


@router.get("/access-log", response_model=list[AccessLogOut])
def list_access_log(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    actor: str | None = None,
    resource: str | None = None,
    action: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> list[AccessLog]:
    stmt = (
        select(AccessLog)
        .where(AccessLog.organization_id == org.id)
        .order_by(AccessLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if actor:
        stmt = stmt.where(AccessLog.actor == actor)
    if resource:
        stmt = stmt.where(AccessLog.resource == resource)
    if action:
        stmt = stmt.where(AccessLog.action == action)
    return list(session.execute(stmt).scalars().all())
