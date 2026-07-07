"""Hard spend enforcement: deny agents that have blown the cost budget/quota.

Agent LLM spend is metered post-hoc as ``MetricEvent.cost_usd``. When
``enforce_cost_budget`` is on, an org over its monthly budget has all its agents
denied (via the quarantine check the SDK consults before each tool call), and an
agent over its per-agent ``agent_cost_quota_usd`` is denied individually. This
turns FinOps tracking into a hard control without touching the ingest path.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import MetricEvent, Organization


def _month_start(now: datetime) -> datetime:
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _spend(
    session: Session, org_id: str, since: datetime, agent_id: str | None = None
) -> float:
    stmt = select(func.coalesce(func.sum(MetricEvent.cost_usd), 0.0)).where(
        MetricEvent.organization_id == org_id,
        MetricEvent.timestamp >= since,
    )
    if agent_id is not None:
        stmt = stmt.where(MetricEvent.agent_id == agent_id)
    return float(session.execute(stmt).scalar_one() or 0.0)


def spend_block_reason(
    session: Session,
    org: Organization,
    *,
    agent_id: str | None,
    now: datetime | None = None,
) -> str | None:
    """Reason this agent is denied for spend, or None. Org budget first, then
    the per-agent quota."""
    now = now or datetime.now(UTC)
    month_start = _month_start(now)

    if (
        org.enforce_cost_budget
        and org.monthly_cost_budget_usd is not None
        and _spend(session, org.id, month_start) >= org.monthly_cost_budget_usd
    ):
        return "organization monthly cost budget exceeded"

    if (
        org.agent_cost_quota_usd is not None
        and agent_id is not None
        and _spend(session, org.id, month_start, agent_id) >= org.agent_cost_quota_usd
    ):
        return "agent monthly cost quota exceeded"

    return None


__all__ = ["spend_block_reason"]
