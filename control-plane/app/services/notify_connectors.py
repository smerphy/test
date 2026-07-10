"""Deliver findings to notification connectors in each vendor's native format.

PagerDuty (Events API v2), Opsgenie (Alerts API), Jira (create issue),
ServiceNow (incident table), Slack (incoming webhook), and a generic OCSF
webhook. Delivery is best-effort, severity-gated, and egress-guarded; connector
secrets are decrypted only at send time.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    ConnectorType,
    Finding,
    NotificationConnector,
    Organization,
)
from app.services._http import owned_client
from app.services.crypto import unseal
from app.services.egress import is_safe_webhook_url
from app.services.forward import build_finding_event

_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
# PagerDuty severity vocabulary.
_PD_SEVERITY: dict[str, str] = {
    "info": "info",
    "low": "warning",
    "medium": "warning",
    "high": "error",
    "critical": "critical",
}
_OPSGENIE_PRIORITY: dict[str, str] = {
    "info": "P5",
    "low": "P4",
    "medium": "P3",
    "high": "P2",
    "critical": "P1",
}


def _rank(sev: str) -> int:
    return _SEVERITY_ORDER.get(sev, 0)


def _summary(finding: Finding) -> str:
    return f"[Ephorate/{finding.severity}] {finding.title}"


def _prepare(
    connector: NotificationConnector, finding: Finding, org: Organization
) -> tuple[str, dict[str, str], Any] | None:
    """Return (url, headers, json_body) for a connector, or None if it can't
    be delivered (missing/unsafe config)."""
    cfg = connector.config or {}
    secret = unseal(connector.secret)
    ctype = connector.type
    sev = str(finding.severity)

    if ctype == ConnectorType.PAGERDUTY:
        if not secret:
            return None
        return (
            "https://events.pagerduty.com/v2/enqueue",
            {"content-type": "application/json"},
            {
                "routing_key": secret,
                "event_action": "trigger",
                "dedup_key": finding.dedup_key,
                "payload": {
                    "summary": _summary(finding),
                    "severity": _PD_SEVERITY.get(sev, "warning"),
                    "source": org.slug,
                    "custom_details": {
                        "category": str(finding.category),
                        "atlas": finding.atlas_technique,
                        "owasp": finding.owasp_llm,
                        "finding_id": finding.id,
                    },
                },
            },
        )

    if ctype == ConnectorType.OPSGENIE:
        if not secret:
            return None
        return (
            "https://api.opsgenie.com/v2/alerts",
            {
                "authorization": f"GenieKey {secret}",
                "content-type": "application/json",
            },
            {
                "message": _summary(finding),
                "alias": finding.dedup_key,
                "description": finding.title,
                "priority": _OPSGENIE_PRIORITY.get(sev, "P3"),
                "tags": [str(finding.category)],
            },
        )

    if ctype == ConnectorType.JIRA:
        instance = str(cfg.get("instance_url", "")).rstrip("/")
        email = cfg.get("email")
        project = cfg.get("project")
        if not instance or not email or not project or not secret:
            return None
        url = f"{instance}/rest/api/2/issue"
        if not is_safe_webhook_url(url):
            return None
        token = base64.b64encode(f"{email}:{secret}".encode()).decode()
        return (
            url,
            {"authorization": f"Basic {token}", "content-type": "application/json"},
            {
                "fields": {
                    "project": {"key": project},
                    "summary": _summary(finding),
                    "description": f"{finding.title}\n\nfinding_id={finding.id}",
                    "issuetype": {"name": cfg.get("issue_type", "Bug")},
                }
            },
        )

    if ctype == ConnectorType.SERVICENOW:
        instance = str(cfg.get("instance_url", "")).rstrip("/")
        user = cfg.get("user")
        if not instance or not user or not secret:
            return None
        url = f"{instance}/api/now/table/incident"
        if not is_safe_webhook_url(url):
            return None
        token = base64.b64encode(f"{user}:{secret}".encode()).decode()
        return (
            url,
            {"authorization": f"Basic {token}", "content-type": "application/json"},
            {
                "short_description": _summary(finding),
                "description": f"{finding.title} (finding_id={finding.id})",
                "urgency": "1" if _rank(sev) >= 3 else "2",
            },
        )

    if ctype == ConnectorType.SLACK:
        url = secret or str(cfg.get("webhook_url", ""))
        if not url or not is_safe_webhook_url(url):
            return None
        return (url, {"content-type": "application/json"}, {"text": _summary(finding)})

    if ctype == ConnectorType.WEBHOOK:
        url = str(cfg.get("url", ""))
        if not url or not is_safe_webhook_url(url):
            return None
        return (url, {"content-type": "application/json"}, build_finding_event(finding, org))

    return None


def _send(
    connector: NotificationConnector,
    finding: Finding,
    org: Organization,
    client: httpx.Client,
) -> bool:
    prepared = _prepare(connector, finding, org)
    if prepared is None:
        connector.last_status = "error"
        connector.last_error = "connector misconfigured or unsafe target"
        return False
    url, headers, body = prepared
    try:
        resp = client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        connector.last_status = "ok"
        connector.last_error = None
        return True
    except httpx.HTTPError as exc:
        connector.last_status = "error"
        connector.last_error = f"{type(exc).__name__}: {exc}"[:1000]
        return False


def deliver_one(
    connector: NotificationConnector,
    finding: Finding,
    org: Organization,
    *,
    http_client: httpx.Client | None = None,
) -> bool:
    """Deliver a finding to a single connector, ignoring the severity gate
    (used by the test endpoint). Never raises."""
    with owned_client(http_client, timeout=10.0) as client:
        return _send(connector, finding, org, client)


def dispatch_finding(
    session: Session,
    finding: Finding,
    org: Organization,
    *,
    http_client: httpx.Client | None = None,
) -> int:
    """Deliver a finding to every enabled connector at/above its min severity.
    Returns the number of successful deliveries. Never raises."""
    connectors = list(
        session.execute(
            select(NotificationConnector).where(
                NotificationConnector.organization_id == org.id,
                NotificationConnector.enabled.is_(True),
            )
        ).scalars()
    )
    if not connectors:
        return 0
    delivered = 0
    with owned_client(http_client, timeout=10.0) as client:
        for connector in connectors:
            if _rank(str(finding.severity)) < _rank(connector.min_severity):
                continue
            if _send(connector, finding, org, client):
                delivered += 1
    return delivered


__all__ = ["deliver_one", "dispatch_finding"]
