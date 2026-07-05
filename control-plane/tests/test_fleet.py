from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Agent, Organization
from app.services.fleet import health_of, heartbeat


def _instant(s: str) -> datetime:
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return (d.astimezone(UTC) if d.tzinfo else d.replace(tzinfo=UTC))


def test_heartbeat_enrolls_then_refreshes(client: TestClient) -> None:
    r = client.post(
        "/agents/heartbeat",
        json={"agent_id": "bot-1", "name": "Research Bot", "sdk_version": "0.1.0"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "bot-1"
    assert body["health"] == "active"
    first_seen = body["first_seen"]

    # Second heartbeat updates last_seen but not first_seen, no duplicate row.
    r2 = client.post("/agents/heartbeat", json={"agent_id": "bot-1"})
    assert _instant(r2.json()["first_seen"]) == _instant(first_seen)
    assert len(client.get("/agents").json()) == 1


def test_list_fleet_and_health(
    client: TestClient, session: Session, org: Organization
) -> None:
    client.post("/agents/heartbeat", json={"agent_id": "fresh"})
    # A stale agent (last seen 30 min ago).
    stale = Agent(
        organization_id=org.id,
        agent_id="stale",
        first_seen=datetime.now(UTC) - timedelta(hours=2),
        last_seen=datetime.now(UTC) - timedelta(minutes=30),
    )
    session.add(stale)
    session.commit()

    fleet = {a["agent_id"]: a["health"] for a in client.get("/agents").json()}
    assert fleet == {"fresh": "active", "stale": "stale"}


def test_health_of_helper(session: Session, org: Organization) -> None:
    a = heartbeat(session, org_id=org.id, agent_id="x")
    session.commit()
    assert health_of(a) == "active"
    a.last_seen = datetime.now(UTC) - timedelta(hours=1)
    assert health_of(a) == "stale"


def test_agent_is_org_scoped(
    client: TestClient, session: Session, org: Organization
) -> None:
    other = Organization(name="Other", slug="other")
    session.add(other)
    session.commit()
    a = heartbeat(session, org_id=other.id, agent_id="rival-bot")
    session.commit()
    assert client.get(f"/agents/{a.id}").status_code == 404
