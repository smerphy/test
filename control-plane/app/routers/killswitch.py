"""Global kill-switch + break-glass administration (EDR emergency stop)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, current_principal, require_role
from app.db import get_session
from app.models import BreakGlassGrant, Organization, Role
from app.schemas import BreakGlassIn, KillSwitchOut
from app.services import killswitch

router = APIRouter(tags=["killswitch"])


def _status(session: Session, org: Organization) -> KillSwitchOut:
    now = datetime.now(UTC)
    grants = session.execute(
        select(BreakGlassGrant)
        .where(BreakGlassGrant.organization_id == org.id)
        .order_by(BreakGlassGrant.expires_at.desc())
    ).scalars()
    active = []
    for g in grants:
        exp = g.expires_at if g.expires_at.tzinfo else g.expires_at.replace(tzinfo=UTC)
        if exp > now:
            active.append(g)
    return KillSwitchOut(halt_all=org.halt_all, active_break_glass=active)


@router.get("/killswitch", response_model=KillSwitchOut)
def get_status(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> KillSwitchOut:
    return _status(session, org)


@router.post("/killswitch/engage", response_model=KillSwitchOut)
def engage(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_role(Role.OWNER)),
) -> KillSwitchOut:
    """Halt every agent in the organization (owner-only emergency stop)."""
    killswitch.engage(session, org, by=principal.user_id)
    return _status(session, org)


@router.post("/killswitch/release", response_model=KillSwitchOut)
def release(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.OWNER)),
) -> KillSwitchOut:
    killswitch.release(session, org)
    return _status(session, org)


@router.post("/killswitch/break-glass", response_model=KillSwitchOut)
def break_glass(
    body: BreakGlassIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_role(Role.ADMIN)),
) -> KillSwitchOut:
    """Grant a time-boxed exception to the kill-switch for one agent."""
    killswitch.grant_break_glass(
        session,
        org,
        agent_id=body.agent_id,
        reason=body.reason,
        minutes=body.minutes,
        by=body.granted_by or principal.user_id,
    )
    return _status(session, org)


@router.get("/whoami/halted")
def am_i_halted(
    agent_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(current_principal),
) -> dict[str, bool]:
    return {"halted": killswitch.is_agent_halted(session, org, agent_id=agent_id)}
