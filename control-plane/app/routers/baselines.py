"""UEBA: per-agent behavioral baselines + drift detection."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.models import AgentBaseline, Organization, Role
from app.schemas import AgentBaselineOut
from app.services.baseline import detect_drift, rebuild_baselines

router = APIRouter(tags=["baselines"])


@router.get("/baselines", response_model=list[AgentBaselineOut])
def list_baselines(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[AgentBaseline]:
    return list(
        session.execute(
            select(AgentBaseline)
            .where(AgentBaseline.organization_id == org.id)
            .order_by(AgentBaseline.event_count.desc())
        ).scalars()
    )


@router.post("/baselines/rebuild")
def rebuild(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> dict[str, int]:
    """Recompute every agent's behavioral baseline from recent history."""
    result = rebuild_baselines(session, org.id)
    session.flush()
    return result


@router.post("/baselines/detect")
def detect(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> dict[str, int]:
    """Run drift detection now: raise findings for agents deviating from their
    baseline (new tools, denial spikes)."""
    result = detect_drift(session, org)
    session.flush()
    return result
