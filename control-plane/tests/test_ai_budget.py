"""BYOK cost budgeting: metering, monthly budget enforcement, usage endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AIUsage, Finding, Organization
from app.services.ai.budget import (
    current_month,
    is_over_budget,
    metered,
    record_usage,
)
from app.settings import get_settings


class StubProvider:
    def __init__(self, responses: list[str]) -> None:
        self._responses = responses
        self._i = 0

    def complete(self, *, system: str, user: str) -> str:
        r = self._responses[min(self._i, len(self._responses) - 1)]
        self._i += 1
        return r


def _enable_ai(session: Session, org: Organization, *, budget: float | None) -> None:
    org.ai_enabled = True
    org.ai_provider = "anthropic"
    org.ai_model = "claude-x"
    org.ai_api_key = "sk-test"
    org.ai_monthly_budget_usd = budget
    session.commit()


def test_record_usage_accrues(session: Session, org: Organization) -> None:
    s = get_settings()
    record_usage(session, org, s, input_tokens=1_000_000, output_tokens=1_000_000)
    session.commit()
    usage = session.query(AIUsage).filter_by(organization_id=org.id).one()
    assert usage.call_count == 1
    # default prices: $3/Mtok in + $15/Mtok out = $18.
    assert round(usage.cost_usd, 2) == 18.0


def test_metered_provider_records(session: Session, org: Organization) -> None:
    s = get_settings()
    provider = metered(StubProvider(["hello world"]), session, org, s)
    provider.complete(system="sys", user="user")
    session.commit()
    usage = session.query(AIUsage).filter_by(organization_id=org.id).one()
    assert usage.call_count == 1
    assert usage.output_tokens >= 1


def test_is_over_budget(session: Session, org: Organization) -> None:
    s = get_settings()
    org.ai_monthly_budget_usd = 10.0
    session.commit()
    assert is_over_budget(session, org, s) is False
    # Push spend over the cap.
    record_usage(session, org, s, input_tokens=1_000_000, output_tokens=1_000_000)
    session.commit()
    assert is_over_budget(session, org, s) is True


def test_no_budget_never_over(session: Session, org: Organization) -> None:
    s = get_settings()
    org.ai_monthly_budget_usd = None
    record_usage(session, org, s, input_tokens=9_000_000, output_tokens=9_000_000)
    session.commit()
    assert is_over_budget(session, org, s) is False


def test_assess_402_when_over_budget(
    session: Session, org: Organization, client: TestClient
) -> None:
    _enable_ai(session, org, budget=1.0)
    # Seed usage already over the $1 budget.
    usage = AIUsage(organization_id=org.id, month=current_month(), cost_usd=5.0)
    session.add(usage)
    session.commit()
    r = client.post("/ai/assess", json={"tool_name": "http.post"})
    assert r.status_code == 402


def test_report_degrades_to_unscored_when_over_budget(
    session: Session, org: Organization, client: TestClient
) -> None:
    _enable_ai(session, org, budget=1.0)
    session.add(AIUsage(organization_id=org.id, month=current_month(), cost_usd=5.0))
    session.commit()
    # Ingestion still works, just unscored (no 402, no provider call).
    r = client.post("/findings/report", json={"observation": "leaked token"})
    assert r.status_code == 201
    f = session.query(Finding).filter_by(organization_id=org.id).one()
    assert f.evidence["ai_rationale"] == "stored without AI scoring"


def test_usage_endpoint(
    session: Session, org: Organization, client: TestClient
) -> None:
    s = get_settings()
    org.ai_monthly_budget_usd = 100.0
    session.commit()
    record_usage(session, org, s, input_tokens=1_000_000, output_tokens=0)
    session.commit()
    r = client.get("/ai/usage")
    assert r.status_code == 200
    body = r.json()
    assert body["input_tokens"] == 1_000_000
    assert body["budget_usd"] == 100.0
    assert body["over_budget"] is False
