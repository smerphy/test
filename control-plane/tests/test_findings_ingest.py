"""Ambient AI-finding ingestion: triage scoring, sweep, dedup, gating, RBAC."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Finding, Organization, risk_score
from app.services.ai.agents import sweep_activity, triage_finding
from app.services.ai.findings_ingest import (
    report_observation,
    run_ai_sweep,
    store_scored_finding,
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


# --- scoring ----------------------------------------------------------------
def test_risk_score_ordering() -> None:
    high = risk_score("critical", "severe", 0.9)
    low = risk_score("low", "minor", 0.9)
    speculative = risk_score("critical", "severe", 0.1)
    assert high > low
    # Low fidelity discounts a severe finding below a confident minor one? No —
    # but it should rank a speculative critical below a confident critical.
    assert speculative < high


def test_triage_finding_scores() -> None:
    provider = StubProvider(
        [
            '{"title":"Hardcoded AWS key in repo","severity":"high",'
            '"impact":"major","category":"data_exfil","actionable":true,'
            '"rationale":"credential exposure"}',
            '{"fidelity":0.82,"reason":"clear secret"}',
        ]
    )
    score = triage_finding(provider, observation="found AKIA... in config")
    assert score.severity == "high"
    assert score.impact == "major"
    assert score.category == "data_exfil"
    assert score.fidelity == 0.82


def test_triage_fallback_on_error() -> None:
    class Boom:
        def complete(self, *, system: str, user: str) -> str:
            from app.services.ai.providers import LLMError

            raise LLMError("down")

    score = triage_finding(Boom(), observation="something", suggested_severity="high")
    assert score.severity == "high"
    assert score.rationale == "stored without AI scoring"


def test_sweep_activity_surfaces_scored_findings() -> None:
    provider = StubProvider(
        [
            '[{"title":"Egress to new host","observation":"data-pipeline posted to '
            'unknown host 12x","severity":"high","impact":"major",'
            '"category":"data_exfil","rationale":"possible exfil"}]',
            '{"fidelity":0.7,"reason":"plausible"}',
        ]
    )
    scores = sweep_activity(provider, activity_digest="...")
    assert len(scores) == 1
    assert scores[0].category == "data_exfil"
    assert scores[0].fidelity == 0.7


# --- storage / dedup --------------------------------------------------------
def test_report_observation_no_ai_defaults(session: Session, org: Organization) -> None:
    f = report_observation(
        session, org, None, observation="suspicious base64 blob in tool output",
        suggested_severity="medium",
    )
    session.commit()
    assert f.source == "agent_report"
    assert f.fidelity == 0.5
    assert f.evidence["observation"].startswith("suspicious base64")


def test_report_observation_dedups(session: Session, org: Organization) -> None:
    provider = StubProvider(
        [
            '{"title":"t","severity":"high","impact":"major","category":"abuse",'
            '"actionable":true,"rationale":"r"}',
            '{"fidelity":0.9}',
        ]
        * 2
    )
    report_observation(session, org, provider, observation="Same observation here")
    report_observation(session, org, provider, observation="same observation here")
    session.commit()
    findings = session.query(Finding).filter_by(organization_id=org.id).all()
    assert len(findings) == 1
    assert findings[0].count == 2


def test_run_ai_sweep_creates_findings(session: Session, org: Organization) -> None:
    provider = StubProvider(
        [
            '[{"title":"Anomalous shell burst","observation":"shell.exec x15 in '
            'one session","severity":"high","impact":"major","category":'
            '"policy_violation","rationale":"burst"}]',
            '{"fidelity":0.75}',
        ]
    )
    result = run_ai_sweep(session, org, provider)
    session.commit()
    assert result["created"] == 1
    f = session.query(Finding).filter_by(organization_id=org.id).one()
    assert f.source == "ai_sweep"


# --- router -----------------------------------------------------------------
def test_report_endpoint(client: TestClient, session: Session, org: Organization) -> None:
    # AI not enabled → stored unscored with defaults.
    r = client.post(
        "/findings/report",
        json={"observation": "leaked API token in log line", "suggested_severity": "high"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["source"] == "agent_report"
    assert body["severity"] == "high"
    assert "risk_score" in body


def test_low_fidelity_hidden_by_default(
    session: Session, org: Organization, client: TestClient
) -> None:
    org.finding_fidelity_threshold = 0.5
    session.commit()
    from app.services.ai.agents import FindingScore

    store_scored_finding(
        session, org,
        score=FindingScore("noisy", "low", "minor", 0.2, "anomaly", "r"),
        source="agent_report", observation="noisy obs",
    )
    store_scored_finding(
        session, org,
        score=FindingScore("solid", "high", "major", 0.9, "data_exfil", "r"),
        source="agent_report", observation="solid obs",
    )
    session.commit()

    default = client.get("/findings").json()
    assert {f["title"] for f in default} == {"solid"}
    allf = client.get("/findings?include_low_fidelity=true").json()
    assert {f["title"] for f in allf} == {"noisy", "solid"}


def test_sweep_endpoint_requires_ai(client: TestClient) -> None:
    assert client.post("/findings/sweep").status_code == 409


def test_report_requires_analyst(monkeypatch, app, org: Organization) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["ro"])
    monkeypatch.setattr(s, "api_key_orgs", {"ro": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"ro": "viewer"})
    c = TestClient(app)
    c.headers.update({"X-API-Key": "ro", "X-Org-Slug": "acme"})
    assert c.post("/findings/report", json={"observation": "x"}).status_code == 403
