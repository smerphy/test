"""Forward findings to external systems (SIEM / SOAR / chat).

When a new finding at or above the org's `finding_min_severity` is raised,
it is POSTed to the org's `finding_webhook_url` as a normalized JSON event
(OCSF-flavored) so Praetor plugs into existing security stacks (Splunk HEC,
Sentinel, Elastic, a SOAR runbook, or Slack). Delivery is best-effort and
egress-guarded (no SSRF to internal addresses).
"""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.models import Finding, FindingSeverity, Organization
from app.services.egress import is_safe_webhook_url

# Ordering for the min-severity threshold.
_SEVERITY_ORDER: dict[str, int] = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}

# OCSF Detection Finding severity_id mapping.
_OCSF_SEVERITY_ID: dict[str, int] = {
    FindingSeverity.INFO: 1,
    FindingSeverity.LOW: 2,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.HIGH: 4,
    FindingSeverity.CRITICAL: 5,
}


def _rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, 0)


def build_finding_event(finding: Finding, org: Organization) -> dict[str, Any]:
    """A normalized, OCSF-flavored 'Detection Finding' (class_uid 2004)."""
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "activity_id": 1,  # Create
        "severity": str(finding.severity),
        "severity_id": _OCSF_SEVERITY_ID.get(str(finding.severity), 0),
        "time": finding.first_seen.isoformat(),
        "message": finding.title,
        "finding_info": {
            "uid": finding.id,
            "title": finding.title,
            "types": [str(finding.category)],
        },
        "metadata": {
            "product": {"name": "Praetor", "vendor_name": "Praetor"},
            "org_id": org.id,
            "org_slug": org.slug,
        },
        "praetor": {
            "rule_id": finding.rule_id,
            "category": str(finding.category),
            "agent_id": finding.agent_id,
            "session_id": finding.session_id,
            "count": finding.count,
            "atlas_technique": finding.atlas_technique,
            "owasp_llm": finding.owasp_llm,
            "evidence": finding.evidence,
        },
    }


def forward_finding(
    session: Session,
    finding_id: str,
    *,
    http_client: httpx.Client | None = None,
) -> bool:
    """POST the finding to the org webhook if configured and severe enough.
    Returns True on delivery, False otherwise. Never raises."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        return False
    org = session.get(Organization, finding.organization_id)
    if org is None or not org.finding_webhook_url:
        return False
    if _rank(str(finding.severity)) < _rank(org.finding_min_severity):
        return False
    if not is_safe_webhook_url(org.finding_webhook_url):
        return False
    client = http_client or httpx.Client(timeout=10.0)
    try:
        r = client.post(
            org.finding_webhook_url, json=build_finding_event(finding, org)
        )
        r.raise_for_status()
        return True
    except Exception:
        return False


__all__ = ["build_finding_event", "forward_finding"]
