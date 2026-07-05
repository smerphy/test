"""SOC console backend: security overview + session forensic timeline."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.models import Organization
from app.services.investigate import security_overview, session_timeline

router = APIRouter(tags=["investigate"])


@router.get("/overview")
def overview(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Org security posture at a glance: open findings by severity/category,
    active quarantines, pending approvals, and 24h decision activity."""
    return security_overview(session, org.id)


@router.get("/timeline/session/{session_id}")
def timeline(
    session_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    """Chronological reconstruction of one agent session: decisions,
    findings, approvals, and quarantines."""
    return session_timeline(session, org.id, session_id)
