"""SOAR response playbooks: matching, action execution, and CRUD API."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Organization,
    ResponsePlaybook,
)
from app.services.quarantine import match_quarantine
from app.services.soar import matches, run_playbooks


def _finding(
    session: Session,
    org: Organization,
    *,
    severity: FindingSeverity = FindingSeverity.CRITICAL,
    category: FindingCategory = FindingCategory.DATA_EXFIL,
    rule_id: str = "injection-exfil",
    agent_id: str | None = "agent-1",
) -> Finding:
    now = datetime.now(UTC)
    f = Finding(
        organization_id=org.id,
        rule_id=rule_id,
        title="Exfil attempt",
        severity=severity,
        category=category,
        dedup_key=f"{rule_id}:{agent_id}",
        first_seen=now,
        last_seen=now,
        agent_id=agent_id,
    )
    session.add(f)
    session.flush()
    return f


def _playbook(
    session: Session,
    org: Organization,
    *,
    name: str = "pb",
    conditions: dict | None = None,
    actions: list[dict] | None = None,
    priority: int = 100,
    stop_on_match: bool = False,
    enabled: bool = True,
) -> ResponsePlaybook:
    pb = ResponsePlaybook(
        organization_id=org.id,
        name=name,
        conditions=conditions or {},
        actions=actions or [],
        priority=priority,
        stop_on_match=stop_on_match,
        enabled=enabled,
    )
    session.add(pb)
    session.flush()
    return pb


# --- matching ---------------------------------------------------------------
def test_matches_conditions(session: Session, org: Organization) -> None:
    f = _finding(session, org, severity=FindingSeverity.HIGH)
    assert matches(_playbook(session, org, name="a", conditions={}), f)
    assert matches(
        _playbook(session, org, name="b", conditions={"min_severity": "high"}), f
    )
    assert not matches(
        _playbook(session, org, name="c", conditions={"min_severity": "critical"}), f
    )
    assert matches(
        _playbook(
            session, org, name="d", conditions={"categories": ["data_exfil"]}
        ),
        f,
    )
    assert not matches(
        _playbook(session, org, name="e", conditions={"categories": ["abuse"]}), f
    )
    assert matches(
        _playbook(
            session, org, name="f", conditions={"rule_ids": ["injection-exfil"]}
        ),
        f,
    )
    assert not matches(
        _playbook(session, org, name="g", conditions={"rule_ids": ["other"]}), f
    )


def test_matches_min_risk_score(session: Session, org: Organization) -> None:
    # critical + moderate impact + full fidelity => risk 50.0.
    f = _finding(session, org, severity=FindingSeverity.CRITICAL)
    assert matches(
        _playbook(session, org, name="lo", conditions={"min_risk_score": 40}), f
    )
    assert not matches(
        _playbook(session, org, name="hi", conditions={"min_risk_score": 60}), f
    )


# --- actions ----------------------------------------------------------------
def test_tag_and_status_and_assign(session: Session, org: Organization) -> None:
    f = _finding(session, org)
    _playbook(
        session,
        org,
        actions=[
            {"type": "tag", "params": {"tags": ["auto", "auto"]}},
            {"type": "set_status", "params": {"status": "triaging"}},
            {"type": "assign", "params": {"assignee": "soc-bot"}},
        ],
    )
    execs = run_playbooks(session, org, f)
    assert len(execs) == 1
    assert all(r["ok"] for r in execs[0].results)
    assert f.evidence["tags"] == ["auto"]  # deduped
    assert f.status == FindingStatus.TRIAGING
    assert f.assignee == "soc-bot"


def test_quarantine_action(session: Session, org: Organization) -> None:
    f = _finding(session, org, agent_id="rogue")
    _playbook(session, org, actions=[{"type": "quarantine"}])
    run_playbooks(session, org, f)
    q = match_quarantine(session, org.id, agent_id="rogue", session_id=None)
    assert q is not None
    assert q.finding_id == f.id


def test_notify_and_forward_actions(session: Session, org: Organization) -> None:
    # No connectors and no SIEM webhook configured: notify delivers to 0 and
    # forward reports not-delivered, but both are recorded without raising.
    f = _finding(session, org)
    _playbook(
        session,
        org,
        actions=[{"type": "notify_connectors"}, {"type": "forward_siem"}],
    )
    execs = run_playbooks(session, org, f)
    results = {r["type"]: r for r in execs[0].results}
    assert results["notify_connectors"]["ok"] is True
    assert "0 connector" in results["notify_connectors"]["detail"]
    assert results["forward_siem"]["ok"] is False


def test_quarantine_noop_without_entity(session: Session, org: Organization) -> None:
    f = _finding(session, org, agent_id=None)
    _playbook(session, org, actions=[{"type": "quarantine"}])
    execs = run_playbooks(session, org, f)
    assert execs[0].results[0]["ok"] is False


def test_unknown_action_recorded_not_raised(
    session: Session, org: Organization
) -> None:
    f = _finding(session, org)
    _playbook(session, org, actions=[{"type": "nope"}])
    execs = run_playbooks(session, org, f)
    assert execs[0].results[0]["ok"] is False
    assert "unknown action" in execs[0].results[0]["detail"]


def test_invalid_status_recorded_not_raised(
    session: Session, org: Organization
) -> None:
    f = _finding(session, org)
    _playbook(
        session, org, actions=[{"type": "set_status", "params": {"status": "bogus"}}]
    )
    execs = run_playbooks(session, org, f)
    assert execs[0].results[0]["ok"] is False


# --- ordering / gating ------------------------------------------------------
def test_disabled_and_nonmatching_dont_fire(
    session: Session, org: Organization
) -> None:
    f = _finding(session, org, severity=FindingSeverity.LOW)
    _playbook(session, org, name="off", enabled=False, actions=[{"type": "tag"}])
    _playbook(
        session,
        org,
        name="nomatch",
        conditions={"min_severity": "critical"},
        actions=[{"type": "tag", "params": {"tags": ["x"]}}],
    )
    assert run_playbooks(session, org, f) == []


def test_stop_on_match_short_circuits(session: Session, org: Organization) -> None:
    f = _finding(session, org)
    _playbook(
        session,
        org,
        name="first",
        priority=10,
        stop_on_match=True,
        actions=[{"type": "tag", "params": {"tags": ["first"]}}],
    )
    _playbook(
        session,
        org,
        name="second",
        priority=20,
        actions=[{"type": "assign", "params": {"assignee": "late"}}],
    )
    execs = run_playbooks(session, org, f)
    assert len(execs) == 1
    assert f.assignee is None  # second playbook never ran


# --- CRUD API ---------------------------------------------------------------
def test_playbook_crud_and_conflict(client: TestClient) -> None:
    body = {
        "name": "isolate-exfil",
        "description": "Quarantine + notify on exfil",
        "priority": 10,
        "stop_on_match": True,
        "conditions": {"min_severity": "high", "categories": ["data_exfil"]},
        "actions": [
            {"type": "quarantine"},
            {"type": "notify_connectors"},
        ],
    }
    r = client.post("/soar/playbooks", json=body)
    assert r.status_code == 201
    pb_id = r.json()["id"]
    assert r.json()["conditions"]["min_severity"] == "high"
    assert len(r.json()["actions"]) == 2

    # Duplicate name → 409.
    assert client.post("/soar/playbooks", json=body).status_code == 409

    # List + get.
    assert len(client.get("/soar/playbooks").json()) == 1
    assert client.get(f"/soar/playbooks/{pb_id}").json()["name"] == "isolate-exfil"

    # Patch.
    r = client.patch(
        f"/soar/playbooks/{pb_id}",
        json={"enabled": False, "actions": [{"type": "tag", "params": {"tags": ["a"]}}]},
    )
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    assert r.json()["actions"] == [{"type": "tag", "params": {"tags": ["a"]}}]

    # Delete.
    assert client.delete(f"/soar/playbooks/{pb_id}").status_code == 204
    assert client.get(f"/soar/playbooks/{pb_id}").status_code == 404


def test_invalid_action_type_rejected(client: TestClient) -> None:
    r = client.post(
        "/soar/playbooks",
        json={"name": "bad", "actions": [{"type": "not-a-real-action"}]},
    )
    assert r.status_code == 422


def test_execution_history_endpoint(
    session: Session, org: Organization, client: TestClient
) -> None:
    f = _finding(session, org)
    _playbook(session, org, actions=[{"type": "tag", "params": {"tags": ["t"]}}])
    run_playbooks(session, org, f)
    session.commit()

    rows = client.get("/soar/executions", params={"finding_id": f.id}).json()
    assert len(rows) == 1
    assert rows[0]["finding_id"] == f.id
    assert rows[0]["results"][0]["type"] == "tag"

    # Filter that matches nothing.
    assert client.get(
        "/soar/executions", params={"finding_id": "missing"}
    ).json() == []
