"""Data-governance endpoints: right-to-erasure (delete-by-subject)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.models import Organization, Role
from app.schemas import EraseSubjectIn, EraseSubjectOut
from app.services.erasure import erase_subject

router = APIRouter(tags=["privacy"])


@router.post("/privacy/erase", response_model=EraseSubjectOut)
def erase(
    body: EraseSubjectIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Erase a data subject's identifier from the mutable stores (findings,
    approvals). Use dry_run first to preview the blast radius. Hash-chained
    audit events are reported, not mutated."""
    return erase_subject(session, org.id, body.subject, dry_run=body.dry_run)
