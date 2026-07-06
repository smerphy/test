"""Quarantines: the EDR kill-switch — isolate an agent/session so the SDK
denies its tool calls. Analysts create/lift manually; the detection engine
creates them automatically for CRITICAL findings (when auto-response is on).

`GET /quarantines/active` is the endpoint the SDK polls to enforce the
kill-switch inline.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import Organization, Quarantine, Role
from app.schemas import QuarantineCheckOut, QuarantineCreateIn, QuarantineOut
from app.services.quarantine import (
    active_quarantines,
    create_quarantine,
    lift_quarantine,
    match_quarantine,
)

router = APIRouter(tags=["quarantines"])


@router.post(
    "/quarantines",
    response_model=QuarantineOut,
    status_code=status.HTTP_201_CREATED,
)
def create(
    body: QuarantineCreateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> Quarantine:
    return create_quarantine(
        session,
        org_id=org.id,
        agent_id=body.agent_id,
        session_id=body.session_id,
        reason=body.reason,
        created_by=body.created_by,
        expires_at=body.expires_at,
    )


@router.get("/quarantines", response_model=list[QuarantineOut])
def list_quarantines(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    active_only: bool = True,
) -> list[Quarantine]:
    if active_only:
        return active_quarantines(session, org.id)
    return list(
        session.execute(
            select(Quarantine)
            .where(Quarantine.organization_id == org.id)
            .order_by(Quarantine.created_at.desc())
            .limit(500)
        ).scalars()
    )


@router.get("/quarantines/active", response_model=list[QuarantineOut])
def list_active(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[Quarantine]:
    """Active quarantines for this org — polled by the SDK to enforce the
    kill-switch inline before evaluating policy."""
    return active_quarantines(session, org.id)


@router.get("/quarantines/check", response_model=QuarantineCheckOut)
def check(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    agent_id: Annotated[str | None, Query()] = None,
    session_id: Annotated[str | None, Query()] = None,
) -> QuarantineCheckOut:
    q = match_quarantine(
        session, org.id, agent_id=agent_id, session_id=session_id
    )
    if q is None:
        return QuarantineCheckOut(quarantined=False)
    return QuarantineCheckOut(quarantined=True, reason=q.reason, quarantine_id=q.id)


@router.post("/quarantines/{quarantine_id}/lift", response_model=QuarantineOut)
def lift(
    quarantine_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
    lifted_by: Annotated[str | None, Query()] = None,
) -> Quarantine:
    q = get_owned(
        session, Quarantine, quarantine_id, org, detail="quarantine not found"
    )
    lift_quarantine(q, lifted_by=lifted_by)
    session.flush()
    return q
