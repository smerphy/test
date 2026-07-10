from __future__ import annotations

import json

import httpx
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Organization,
)
from app.services.forward import build_finding_event, forward_finding


def _finding(
    session: Session,
    org: Organization,
    *,
    severity: FindingSeverity = FindingSeverity.CRITICAL,
) -> Finding:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    f = Finding(
        organization_id=org.id,
        rule_id="injection-exfil-killchain",
        title="kill chain",
        severity=severity,
        category=FindingCategory.DATA_EXFIL,
        status=FindingStatus.OPEN,
        agent_id="agent-x",
        session_id="sess-x",
        dedup_key="k",
        count=1,
        first_seen=now,
        last_seen=now,
        evidence={"exfil_event_ids": ["e1"]},
        atlas_technique="AML.T0024",
        owasp_llm="LLM02",
    )
    session.add(f)
    session.commit()
    return f


def _client(handler: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


def test_payload_is_ocsf_flavored(session: Session, org: Organization) -> None:
    f = _finding(session, org)
    ev = build_finding_event(f, org)
    assert ev["class_uid"] == 2004
    assert ev["severity_id"] == 5  # critical
    assert ev["finding_info"]["uid"] == f.id
    assert ev["ephorate"]["atlas_technique"] == "AML.T0024"
    assert ev["metadata"]["org_slug"] == org.slug


def test_forwards_when_configured_and_severe(
    session: Session, org: Organization
) -> None:
    org.finding_webhook_url = "https://example.com/siem"
    org.finding_min_severity = "high"
    f = _finding(session, org, severity=FindingSeverity.CRITICAL)
    posted: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        return httpx.Response(200)

    assert forward_finding(session, f.id, http_client=_client(handler)) is True
    assert posted[0]["finding_info"]["uid"] == f.id


def test_not_forwarded_below_threshold(session: Session, org: Organization) -> None:
    org.finding_webhook_url = "https://example.com/siem"
    org.finding_min_severity = "critical"
    f = _finding(session, org, severity=FindingSeverity.MEDIUM)
    # Should never call the webhook.
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200)

    assert forward_finding(session, f.id, http_client=_client(handler)) is False
    assert called["n"] == 0


def test_not_forwarded_when_unconfigured(session: Session, org: Organization) -> None:
    f = _finding(session, org)
    assert forward_finding(session, f.id) is False


def test_org_endpoint_rejects_internal_forward_url(client) -> None:
    r = client.patch(
        "/org", json={"finding_webhook_url": "http://169.254.169.254/x"}
    )
    assert r.status_code == 422


def test_org_endpoint_sets_forward_config(client) -> None:
    r = client.patch(
        "/org",
        json={
            "finding_webhook_url": "https://example.com/siem",
            "finding_min_severity": "medium",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["finding_webhook_url"] == "https://example.com/siem"
    assert body["finding_min_severity"] == "medium"
