"""Financial tracking: cost summary, budget forecast, endpoints + config."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AIUsage, MetricEvent, Organization
from app.services.finance import budget_status, cost_summary


def _metric(
    session: Session,
    org: Organization,
    *,
    ts: datetime,
    model: str = "claude-sonnet-4-6",
    agent_id: str = "agent-1",
    project_id: str | None = None,
    cost: float = 0.0,
    in_tok: int = 0,
    out_tok: int = 0,
    status: str = "success",
) -> None:
    session.add(
        MetricEvent(
            organization_id=org.id,
            project_id=project_id,
            timestamp=ts,
            agent_id=agent_id,
            model=model,
            duration_ms=100,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=cost,
            status=status,
        )
    )


# --- cost_summary -----------------------------------------------------------
def test_cost_summary_breakdowns_and_totals(
    session: Session, org: Organization
) -> None:
    now = datetime(2026, 6, 15, 12, tzinfo=UTC)
    _metric(
        session, org, ts=now, model="claude-opus-4-8", agent_id="a",
        cost=6.0, in_tok=100, out_tok=50,
    )
    _metric(
        session, org, ts=now, model="claude-sonnet-4-6", agent_id="b",
        cost=3.0, in_tok=200, out_tok=20,
    )
    _metric(
        session, org, ts=now, model="claude-sonnet-4-6", agent_id="a",
        cost=1.0, status="error",
    )
    session.commit()

    summary = cost_summary(
        session,
        org_id=org.id,
        since=now - timedelta(hours=1),
        until=now + timedelta(hours=1),
    )
    assert summary["total"]["cost_usd"] == 10.0
    assert summary["total"]["calls"] == 3
    assert summary["total"]["errors"] == 1
    assert summary["total"]["total_tokens"] == 370

    # Model ranking: opus (6.0) leads sonnet (4.0); shares sum sensibly.
    models = summary["by_model"]
    assert models[0]["key"] == "claude-opus-4-8"
    assert models[0]["cost_usd"] == 6.0
    assert models[0]["share"] == 0.6
    assert models[1]["key"] == "claude-sonnet-4-6"
    assert models[1]["cost_usd"] == 4.0

    # Agent ranking: agent "a" (6.0 + 1.0) leads "b" (3.0).
    agents = {a["key"]: a for a in summary["by_agent"]}
    assert agents["a"]["cost_usd"] == 7.0
    assert agents["b"]["cost_usd"] == 3.0

    # No project → the "<none>" bucket.
    assert summary["by_project"][0]["key"] == "<none>"


def test_cost_summary_daily_trend_and_window(
    session: Session, org: Organization
) -> None:
    d1 = datetime(2026, 6, 10, 9, tzinfo=UTC)
    d2 = datetime(2026, 6, 11, 9, tzinfo=UTC)
    _metric(session, org, ts=d1, cost=2.0)
    _metric(session, org, ts=d2, cost=5.0)
    # Outside the window — excluded.
    _metric(session, org, ts=datetime(2026, 5, 1, tzinfo=UTC), cost=99.0)
    session.commit()

    summary = cost_summary(
        session,
        org_id=org.id,
        since=datetime(2026, 6, 1, tzinfo=UTC),
        until=datetime(2026, 6, 30, tzinfo=UTC),
    )
    assert summary["total"]["cost_usd"] == 7.0
    days = {d["day"]: d["cost_usd"] for d in summary["daily"]}
    assert days == {"2026-06-10": 2.0, "2026-06-11": 5.0}


def test_cost_summary_empty(session: Session, org: Organization) -> None:
    summary = cost_summary(
        session,
        org_id=org.id,
        since=datetime(2026, 1, 1, tzinfo=UTC),
        until=datetime(2026, 2, 1, tzinfo=UTC),
    )
    assert summary["total"] == {
        "cost_usd": 0.0,
        "calls": 0,
        "total_tokens": 0,
        "errors": 0,
        "error_rate": 0.0,
        "avg_cost_per_call": 0.0,
    }
    assert summary["by_model"] == []
    assert summary["daily"] == []


# --- budget_status ----------------------------------------------------------
def test_budget_status_forecast(session: Session, org: Organization) -> None:
    org.monthly_cost_budget_usd = 100.0
    now = datetime(2026, 6, 15, tzinfo=UTC)  # 14 days elapsed, 30-day month
    _metric(session, org, ts=datetime(2026, 6, 10, tzinfo=UTC), cost=70.0)
    # Previous month — must not count toward this month's spend.
    _metric(session, org, ts=datetime(2026, 5, 20, tzinfo=UTC), cost=500.0)
    session.commit()

    status = budget_status(session, org, now=now)
    assert status["month"] == "2026-06"
    assert status["agent_spend_usd"] == 70.0
    assert status["budget_usd"] == 100.0
    assert status["pct_used"] == 0.7
    assert status["days_in_month"] == 30
    # 70 over 14 days -> 5/day -> 150 projected -> over the 100 budget.
    assert status["projected_month_usd"] == 150.0
    assert status["forecast_over_budget"] is True


def test_budget_status_no_budget_and_advisory(
    session: Session, org: Organization
) -> None:
    now = datetime(2026, 6, 15, tzinfo=UTC)
    session.add(
        AIUsage(
            organization_id=org.id,
            month="2026-06",
            input_tokens=1000,
            output_tokens=500,
            cost_usd=4.25,
            call_count=3,
            alerted=False,
        )
    )
    session.commit()
    status = budget_status(session, org, now=now)
    assert status["budget_usd"] is None
    assert status["pct_used"] is None
    assert status["forecast_over_budget"] is False
    assert status["advisory_spend_usd"] == 4.25


# --- endpoints + config -----------------------------------------------------
def test_finance_endpoints(client: TestClient) -> None:
    r = client.get("/finance/summary")
    assert r.status_code == 200
    body = r.json()
    assert "total" in body and "by_model" in body and "daily" in body

    r = client.get("/finance/budget")
    assert r.status_code == 200
    assert "projected_month_usd" in r.json()


def test_set_cost_budget_via_org_patch(client: TestClient) -> None:
    r = client.patch("/org", json={"monthly_cost_budget_usd": 250.0})
    assert r.status_code == 200
    assert r.json()["monthly_cost_budget_usd"] == 250.0
    assert client.get("/finance/budget").json()["budget_usd"] == 250.0

    # Present-but-null clears it.
    r = client.patch("/org", json={"monthly_cost_budget_usd": None})
    assert r.status_code == 200
    assert r.json()["monthly_cost_budget_usd"] is None

    # Negative budgets are rejected.
    assert client.patch("/org", json={"monthly_cost_budget_usd": -5}).status_code == 422
