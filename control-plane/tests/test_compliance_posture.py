"""AI compliance posture: framework catalog + live control mapping."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    AgentBaseline,
    DetectionRule,
    Finding,
    FindingCategory,
    FindingSeverity,
    Organization,
    PolicyBundle,
    Project,
    ResponsePlaybook,
    ThreatFeed,
)
from app.services.compliance_posture import (
    collect_signals,
    compute_posture,
    list_frameworks,
    posture_overview,
)


def _fully_configure(session: Session, org: Organization) -> None:
    """Turn on every configuration-dependent control for the org."""
    org.auto_quarantine = True
    org.pii_redaction_enabled = True
    org.finding_webhook_url = "https://siem.example/hec"
    org.monthly_cost_budget_usd = 1000.0
    project = Project(organization_id=org.id, name="p", slug="p")
    session.add(project)
    session.flush()
    session.add(PolicyBundle(project_id=project.id, name="b"))
    session.add(
        DetectionRule(
            organization_id=org.id,
            name="r",
            enabled=True,
            severity="high",
            category="prompt_injection",
            spec={},
        )
    )
    session.add(
        ResponsePlaybook(
            organization_id=org.id, name="pb", conditions={}, actions=[]
        )
    )
    session.add(
        ThreatFeed(organization_id=org.id, name="feed", format="stix")
    )
    now = datetime.now(UTC)
    session.add(
        AgentBaseline(
            organization_id=org.id,
            agent_id="a",
            window_start=now,
            window_end=now,
        )
    )
    session.flush()


# --- catalog ----------------------------------------------------------------
def test_list_frameworks_catalog() -> None:
    frameworks = list_frameworks()
    keys = {f["key"] for f in frameworks}
    assert keys == {"nist_ai_rmf", "eu_ai_act", "owasp_llm"}
    for fw in frameworks:
        assert fw["controls"]
        for c in fw["controls"]:
            assert c["id"] and c["signals"]


# --- signals ----------------------------------------------------------------
def test_signals_bare_vs_configured(session: Session, org: Organization) -> None:
    bare = collect_signals(session, org)
    # Platform guarantees are always on; config-dependent controls are off.
    assert bare.audit_trail and bare.kill_switch and bare.human_approval
    assert not bare.policy_enforcement
    assert not bare.soar_playbooks
    assert not bare.threat_intel

    _fully_configure(session, org)
    full = collect_signals(session, org)
    assert full.policy_enforcement
    assert full.custom_detections
    assert full.auto_quarantine
    assert full.pii_redaction
    assert full.incident_notification
    assert full.soar_playbooks
    assert full.cost_controls
    assert full.threat_intel
    assert full.behavioral_baselines


# --- posture ----------------------------------------------------------------
def test_bare_org_has_gaps_but_platform_controls_hold(
    session: Session, org: Organization
) -> None:
    posture = compute_posture(session, org, "nist_ai_rmf")
    assert posture["framework"] == "nist_ai_rmf"
    assert 0.0 < posture["coverage"] < 1.0
    by_id = {c["id"]: c for c in posture["controls"]}
    # Audit/accountability is a platform guarantee → satisfied even bare.
    assert by_id["GOVERN-4.1"]["status"] == "satisfied"
    # Response plans need SOAR/auto-quarantine → gap, with remediation.
    assert by_id["MANAGE-2.1"]["status"] == "gap"
    assert by_id["MANAGE-2.1"]["remediation"]


def test_full_configuration_reaches_full_coverage(
    session: Session, org: Organization
) -> None:
    _fully_configure(session, org)
    posture = compute_posture(session, org, "nist_ai_rmf")
    assert posture["coverage"] == 1.0
    assert posture["controls_gap"] == 0
    assert all(c["status"] == "satisfied" for c in posture["controls"])


def test_partial_status_when_some_signals_present(
    session: Session, org: Organization
) -> None:
    # EU AI Act Article-15 needs detections + threat_intel + baselines.
    # Give it only custom detections → partial.
    session.add(
        DetectionRule(
            organization_id=org.id,
            name="r",
            enabled=True,
            severity="high",
            category="prompt_injection",
            spec={},
        )
    )
    session.flush()
    posture = compute_posture(session, org, "eu_ai_act")
    art15 = next(c for c in posture["controls"] if c["id"] == "Article-15")
    assert art15["status"] == "partial"
    assert "custom_detections" in art15["present_signals"]
    assert "threat_intel" in art15["missing_signals"]


def test_open_critical_findings_surfaced(
    session: Session, org: Organization
) -> None:
    now = datetime.now(UTC)
    session.add(
        Finding(
            organization_id=org.id,
            rule_id="r",
            title="t",
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.DATA_EXFIL,
            dedup_key="k",
            first_seen=now,
            last_seen=now,
        )
    )
    session.flush()
    posture = compute_posture(session, org, "owasp_llm")
    assert posture["open_critical_findings"] == 1


def test_overview_covers_all_frameworks(
    session: Session, org: Organization
) -> None:
    overview = posture_overview(session, org)
    keys = {f["framework"] for f in overview["frameworks"]}
    assert keys == {"nist_ai_rmf", "eu_ai_act", "owasp_llm"}
    for f in overview["frameworks"]:
        assert 0.0 <= f["coverage"] <= 1.0
        assert (
            f["controls_satisfied"] + f["controls_partial"] + f["controls_gap"]
            == f["controls_total"]
        )
    # Full configuration lifts every framework's coverage.
    before = {f["framework"]: f["coverage"] for f in overview["frameworks"]}
    _fully_configure(session, org)
    after = {
        f["framework"]: f["coverage"]
        for f in posture_overview(session, org)["frameworks"]
    }
    assert all(after[k] >= before[k] for k in before)


# --- API --------------------------------------------------------------------
def test_frameworks_endpoint(client: TestClient) -> None:
    rows = client.get("/compliance/frameworks").json()
    assert {f["key"] for f in rows} == {"nist_ai_rmf", "eu_ai_act", "owasp_llm"}


def test_posture_endpoint_and_unknown_framework(client: TestClient) -> None:
    r = client.get("/compliance/posture/eu_ai_act")
    assert r.status_code == 200
    assert r.json()["framework"] == "eu_ai_act"
    assert "controls" in r.json()

    assert client.get("/compliance/posture/bogus").status_code == 404


def test_posture_overview_endpoint(client: TestClient) -> None:
    r = client.get("/compliance/posture")
    assert r.status_code == 200
    body = r.json()
    assert len(body["frameworks"]) == 3
    assert "open_critical_findings" in body
