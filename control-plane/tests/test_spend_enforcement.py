"""Hard spend enforcement: over-budget orgs / over-quota agents are denied
inline via the quarantine check the SDK consults before each tool call."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import MetricEvent, Organization
from app.services.spend_guard import spend_block_reason


def _spend(
    session: Session, org: Organization, *, agent_id: str, cost: float
) -> None:
    session.add(
        MetricEvent(
            organization_id=org.id,
            timestamp=datetime.now(UTC),
            agent_id=agent_id,
            model="claude-opus-4",
            duration_ms=100,
            cost_usd=cost,
            status="success",
        )
    )
    session.flush()


# --- service ----------------------------------------------------------------
def test_no_enforcement_never_blocks(session: Session, org: Organization) -> None:
    org.monthly_cost_budget_usd = 10.0  # tracking only; enforcement off
    _spend(session, org, agent_id="a", cost=50.0)
    assert spend_block_reason(session, org, agent_id="a") is None


def test_org_budget_blocks_every_agent(session: Session, org: Organization) -> None:
    org.monthly_cost_budget_usd = 10.0
    org.enforce_cost_budget = True
    _spend(session, org, agent_id="a", cost=6.0)
    _spend(session, org, agent_id="b", cost=6.0)  # org total 12 > 10
    session.flush()
    assert spend_block_reason(session, org, agent_id="a") is not None
    assert spend_block_reason(session, org, agent_id="b") is not None
    # Even an agent with no spend of its own is denied once the org is over.
    assert spend_block_reason(session, org, agent_id="c") is not None


def test_org_under_budget_passes(session: Session, org: Organization) -> None:
    org.monthly_cost_budget_usd = 10.0
    org.enforce_cost_budget = True
    _spend(session, org, agent_id="a", cost=4.0)
    assert spend_block_reason(session, org, agent_id="a") is None


def test_agent_quota_blocks_only_that_agent(
    session: Session, org: Organization
) -> None:
    org.agent_cost_quota_usd = 5.0
    _spend(session, org, agent_id="hog", cost=6.0)
    _spend(session, org, agent_id="lean", cost=1.0)
    session.flush()
    assert spend_block_reason(session, org, agent_id="hog") is not None
    assert spend_block_reason(session, org, agent_id="lean") is None
    # A missing agent_id can't be quota-checked.
    assert spend_block_reason(session, org, agent_id=None) is None


# --- EDR integration + org settings API -------------------------------------
def test_over_budget_denied_via_quarantine_check(
    session: Session, org: Organization, client: TestClient
) -> None:
    org.monthly_cost_budget_usd = 10.0
    org.enforce_cost_budget = True
    _spend(session, org, agent_id="a", cost=12.0)
    session.commit()

    chk = client.get("/quarantines/check", params={"agent_id": "a"}).json()
    assert chk["quarantined"] is True
    assert "budget" in chk["reason"]


def test_agent_quota_denied_via_quarantine_check(
    session: Session, org: Organization, client: TestClient
) -> None:
    org.agent_cost_quota_usd = 5.0
    _spend(session, org, agent_id="hog", cost=6.0)
    _spend(session, org, agent_id="lean", cost=1.0)
    session.commit()

    assert (
        client.get("/quarantines/check", params={"agent_id": "hog"}).json()[
            "quarantined"
        ]
        is True
    )
    assert (
        client.get("/quarantines/check", params={"agent_id": "lean"}).json()[
            "quarantined"
        ]
        is False
    )


def test_org_patch_sets_enforcement_fields(client: TestClient) -> None:
    r = client.patch(
        "/org",
        json={"enforce_cost_budget": True, "agent_cost_quota_usd": 25.0},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["enforce_cost_budget"] is True
    assert body["agent_cost_quota_usd"] == 25.0

    # Present-but-null clears the per-agent quota.
    r = client.patch("/org", json={"agent_cost_quota_usd": None})
    assert r.status_code == 200
    assert r.json()["agent_cost_quota_usd"] is None
