"""Financial tracking (FinOps) over agent LLM spend.

Every agent Claude/LLM call is metered as a :class:`MetricEvent` carrying
``cost_usd`` (authoritative from the SDK, or the server-side price-book
fallback). This module turns that stream into the numbers a finance/platform
owner needs:

* :func:`cost_summary` — spend over a window, broken down by model, agent, and
  project, plus a daily trend and top spenders. Chargeback/showback in one call.
* :func:`budget_status` — month-to-date agent spend versus the org's monthly
  cost budget, with a linear end-of-month forecast (burn rate) and the separate
  Praetor advisory (BYOK) spend alongside.

Aggregation is computed in Python over one indexed window scan, matching
``app.services.metrics`` — portable across SQLite (tests) and Postgres. At
scale this moves to SQL ``date_bin``/``GROUP BY``.
"""

from __future__ import annotations

import calendar
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AIUsage, MetricEvent, Organization
from app.services.ai.budget import current_month

_NO_PROJECT = "<none>"


def _month_start(now: datetime) -> datetime:
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


class _Acc:
    """Running cost/usage accumulator for one breakdown key."""

    __slots__ = ("calls", "cost", "errors", "tokens")

    def __init__(self) -> None:
        self.cost = 0.0
        self.calls = 0
        self.tokens = 0
        self.errors = 0

    def add(self, cost: float, tokens: int, is_error: bool) -> None:
        self.cost += cost
        self.calls += 1
        self.tokens += tokens
        if is_error:
            self.errors += 1


def _ranked(accs: dict[str, _Acc], total_cost: float, top: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = [
        {
            "key": key,
            "cost_usd": round(a.cost, 6),
            "calls": a.calls,
            "total_tokens": a.tokens,
            "errors": a.errors,
            "share": round(a.cost / total_cost, 4) if total_cost > 0 else 0.0,
        }
        for key, a in accs.items()
    ]
    items.sort(key=lambda d: d["cost_usd"], reverse=True)
    return items[:top]


def cost_summary(
    session: Session,
    *,
    org_id: str,
    since: datetime,
    until: datetime,
    top: int = 10,
) -> dict[str, Any]:
    """Spend over ``[since, until)`` broken down by model / agent / project,
    with a daily trend and overall totals."""
    rows = session.execute(
        select(
            MetricEvent.model,
            MetricEvent.agent_id,
            MetricEvent.project_id,
            MetricEvent.timestamp,
            MetricEvent.input_tokens,
            MetricEvent.output_tokens,
            MetricEvent.cost_usd,
            MetricEvent.status,
        ).where(
            MetricEvent.organization_id == org_id,
            MetricEvent.timestamp >= since,
            MetricEvent.timestamp < until,
        )
    ).all()

    total = _Acc()
    by_model: dict[str, _Acc] = defaultdict(_Acc)
    by_agent: dict[str, _Acc] = defaultdict(_Acc)
    by_project: dict[str, _Acc] = defaultdict(_Acc)
    by_day: dict[str, _Acc] = defaultdict(_Acc)

    for r in rows:
        tokens = int(r.input_tokens) + int(r.output_tokens)
        cost = float(r.cost_usd)
        is_error = r.status != "success"
        total.add(cost, tokens, is_error)
        by_model[r.model].add(cost, tokens, is_error)
        by_agent[r.agent_id].add(cost, tokens, is_error)
        by_project[r.project_id or _NO_PROJECT].add(cost, tokens, is_error)
        ts = r.timestamp
        day = (ts if ts.tzinfo else ts.replace(tzinfo=UTC)).astimezone(UTC).strftime(
            "%Y-%m-%d"
        )
        by_day[day].add(cost, tokens, is_error)

    daily = [
        {
            "day": day,
            "cost_usd": round(by_day[day].cost, 6),
            "calls": by_day[day].calls,
            "total_tokens": by_day[day].tokens,
        }
        for day in sorted(by_day)
    ]

    return {
        "since": since.isoformat(),
        "until": until.isoformat(),
        "total": {
            "cost_usd": round(total.cost, 6),
            "calls": total.calls,
            "total_tokens": total.tokens,
            "errors": total.errors,
            "error_rate": round(total.errors / total.calls, 4) if total.calls else 0.0,
            "avg_cost_per_call": round(total.cost / total.calls, 6)
            if total.calls
            else 0.0,
        },
        "by_model": _ranked(by_model, total.cost, top),
        "by_agent": _ranked(by_agent, total.cost, top),
        "by_project": _ranked(by_project, total.cost, top),
        "daily": daily,
    }


def budget_status(
    session: Session,
    org: Organization,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Month-to-date agent spend vs the monthly cost budget, with a linear
    end-of-month forecast, plus the advisory (BYOK) spend for context."""
    now = now or datetime.now(UTC)
    month_start = _month_start(now)

    rows = session.execute(
        select(MetricEvent.cost_usd).where(
            MetricEvent.organization_id == org.id,
            MetricEvent.timestamp >= month_start,
        )
    ).all()
    agent_spend = round(sum(float(r.cost_usd) for r in rows), 6)

    days_in_month = calendar.monthrange(now.year, now.month)[1]
    # Fractional days elapsed so the forecast doesn't jump at midnight.
    days_elapsed = (now - month_start).total_seconds() / 86400
    days_elapsed = max(days_elapsed, 1e-9)
    daily_burn = agent_spend / days_elapsed
    projected = round(daily_burn * days_in_month, 6)

    budget = org.monthly_cost_budget_usd
    pct_used = round(agent_spend / budget, 4) if budget else None
    forecast_over = bool(budget is not None and projected > budget)

    # Praetor's own advisory (BYOK) spend for the same month, for context.
    advisory = session.execute(
        select(AIUsage).where(
            AIUsage.organization_id == org.id,
            AIUsage.month == current_month(now),
        )
    ).scalar_one_or_none()
    advisory_spend = round(advisory.cost_usd, 6) if advisory is not None else 0.0

    return {
        "month": current_month(now),
        "agent_spend_usd": agent_spend,
        "budget_usd": budget,
        "pct_used": pct_used,
        "projected_month_usd": projected,
        "forecast_over_budget": forecast_over,
        "daily_burn_usd": round(daily_burn, 6),
        "days_elapsed": round(days_elapsed, 2),
        "days_in_month": days_in_month,
        "advisory_spend_usd": advisory_spend,
        "advisory_budget_usd": org.ai_monthly_budget_usd,
    }


__all__ = ["budget_status", "cost_summary"]
