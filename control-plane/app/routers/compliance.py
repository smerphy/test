"""AI compliance posture: framework catalog + live control-mapping report.

Read-only and SOC/GRC-facing (ANALYST). Complements the period-based evidence
report at /reports/compliance with a point-in-time posture assessment.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.models import Organization, Role
from app.services.compliance_posture import (
    compute_posture,
    known_framework,
    list_frameworks,
)

router = APIRouter(tags=["compliance"])


@router.get("/compliance/frameworks")
def get_frameworks(
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> list[dict[str, Any]]:
    """The static framework catalog (NIST AI RMF, EU AI Act, OWASP LLM)."""
    return list_frameworks()


@router.get("/compliance/posture/{framework}")
def get_posture(
    framework: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Live posture assessment of the org against one framework."""
    if not known_framework(framework):
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail=f"unknown framework {framework!r}",
        )
    return compute_posture(session, org, framework)
