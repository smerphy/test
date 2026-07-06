"""Financial tracking (FinOps): agent LLM spend, breakdowns, and budget.

Read surface for the cost of running agents — sourced from metered Claude/LLM
calls (MetricEvent.cost_usd). Viewer-readable; the monthly cost budget that
powers the forecast is configured via PATCH /org (admin).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.models import Organization
from app.services.finance import budget_status, cost_summary

router = APIRouter(tags=["finance"])


@router.get("/finance/summary")
def get_cost_summary(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    since: datetime | None = None,
    until: datetime | None = None,
    top: Annotated[int, Query(ge=1, le=100)] = 10,
) -> dict[str, Any]:
    """Agent LLM spend over a window, broken down by model / agent / project
    with a daily trend. Defaults to the last 30 days."""
    now = datetime.now(UTC)
    if until is None:
        until = now
    if since is None:
        since = until - timedelta(days=30)
    return cost_summary(session, org_id=org.id, since=since, until=until, top=top)


@router.get("/finance/budget")
def get_budget_status(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Month-to-date agent spend vs the monthly cost budget, with a linear
    end-of-month forecast and the advisory (BYOK) spend alongside."""
    return budget_status(session, org)
