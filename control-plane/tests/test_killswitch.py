"""Global kill-switch + break-glass exceptions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Organization
from app.services import killswitch


# --- service ----------------------------------------------------------------
def test_halt_isolates_all_agents(session: Session, org: Organization) -> None:
    assert killswitch.is_agent_halted(session, org, agent_id="a") is False
    killswitch.engage(session, org)
    assert killswitch.is_agent_halted(session, org, agent_id="a") is True
    assert killswitch.is_agent_halted(session, org, agent_id=None) is True


def test_break_glass_exempts_one_agent(session: Session, org: Organization) -> None:
    killswitch.engage(session, org)
    killswitch.grant_break_glass(
        session, org, agent_id="remediator", reason="fix", minutes=30
    )
    session.flush()
    assert killswitch.is_agent_halted(session, org, agent_id="remediator") is False
    # Other agents stay halted.
    assert killswitch.is_agent_halted(session, org, agent_id="other") is True


def test_break_glass_expires(session: Session, org: Organization) -> None:
    killswitch.engage(session, org)
    g = killswitch.grant_break_glass(
        session, org, agent_id="r", reason="x", minutes=30
    )
    g.expires_at = datetime.now(UTC) - timedelta(minutes=1)  # already expired
    session.flush()
    assert killswitch.is_agent_halted(session, org, agent_id="r") is True


def test_release_clears_halt(session: Session, org: Organization) -> None:
    killswitch.engage(session, org)
    killswitch.release(session, org)
    assert killswitch.is_agent_halted(session, org, agent_id="a") is False


# --- endpoints + EDR integration --------------------------------------------
def test_killswitch_flow_via_api(client: TestClient) -> None:
    assert client.get("/killswitch").json()["halt_all"] is False

    # Engage → the quarantine check now isolates any agent.
    assert client.post("/killswitch/engage").json()["halt_all"] is True
    chk = client.get("/quarantines/check", params={"agent_id": "a1"}).json()
    assert chk["quarantined"] is True
    assert "kill-switch" in chk["reason"]

    # Break-glass exempts one agent.
    r = client.post(
        "/killswitch/break-glass",
        json={"agent_id": "a1", "reason": "remediation", "minutes": 30},
    )
    assert r.status_code == 200
    assert len(r.json()["active_break_glass"]) == 1
    assert (
        client.get("/quarantines/check", params={"agent_id": "a1"}).json()[
            "quarantined"
        ]
        is False
    )
    # A different agent is still halted.
    assert (
        client.get("/quarantines/check", params={"agent_id": "a2"}).json()[
            "quarantined"
        ]
        is True
    )

    # Release.
    assert client.post("/killswitch/release").json()["halt_all"] is False
    assert (
        client.get("/quarantines/check", params={"agent_id": "a2"}).json()[
            "quarantined"
        ]
        is False
    )
