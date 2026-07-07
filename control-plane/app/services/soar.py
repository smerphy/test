"""SOAR playbook engine: run automated response actions on new findings.

``run_playbooks`` is invoked by the detection engine for each newly created
finding. It evaluates enabled playbooks in priority order, executes the actions
of every matching playbook (unless one with ``stop_on_match`` short-circuits the
rest), and records a ``PlaybookExecution`` per fired playbook for audit.

Actions never raise: a connector/webhook failure is captured as ``ok: False`` in
the execution record so one broken step can't wedge the detection run.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    FindingStatus,
    Organization,
    PlaybookExecution,
    QuarantineSource,
    ResponsePlaybook,
)
from app.models.finding import risk_score
from app.services.forward import forward_finding
from app.services.notify_connectors import dispatch_finding
from app.services.quarantine import create_quarantine, match_quarantine

_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _sev_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(str(severity), 0)


def matches(playbook: ResponsePlaybook, finding: Finding) -> bool:
    """Every present condition clause must hold (empty conditions match all)."""
    c = playbook.conditions or {}

    min_sev = c.get("min_severity")
    if min_sev is not None and _sev_rank(str(finding.severity)) < _sev_rank(min_sev):
        return False

    categories = c.get("categories")
    if categories and str(finding.category) not in set(categories):
        return False

    rule_ids = c.get("rule_ids")
    if rule_ids and finding.rule_id not in set(rule_ids):
        return False

    sources = c.get("sources")
    if sources and str(finding.source) not in set(sources):
        return False

    min_risk = c.get("min_risk_score")
    if min_risk is not None:
        score = risk_score(
            str(finding.severity), str(finding.impact), finding.fidelity
        )
        if score < float(min_risk):
            return False

    return True


def _act_quarantine(
    session: Session, org: Organization, finding: Finding, params: dict[str, Any]
) -> tuple[bool, str]:
    if finding.agent_id is None and finding.session_id is None:
        return False, "finding has no agent/session to isolate"
    if (
        match_quarantine(
            session, org.id, agent_id=finding.agent_id, session_id=finding.session_id
        )
        is not None
    ):
        return True, "entity already quarantined"
    create_quarantine(
        session,
        org_id=org.id,
        agent_id=finding.agent_id,
        session_id=finding.session_id,
        reason=f"SOAR playbook response: {finding.title}",
        source=QuarantineSource.AUTO,
        finding_id=finding.id,
    )
    return True, "entity quarantined"


def _act_notify(
    session: Session, org: Organization, finding: Finding, params: dict[str, Any]
) -> tuple[bool, str]:
    delivered = dispatch_finding(session, finding, org)
    return True, f"delivered to {delivered} connector(s)"


def _act_forward(
    session: Session, org: Organization, finding: Finding, params: dict[str, Any]
) -> tuple[bool, str]:
    ok = forward_finding(session, finding.id)
    return ok, "forwarded to SIEM" if ok else "SIEM webhook not configured/delivered"


def _act_tag(
    session: Session, org: Organization, finding: Finding, params: dict[str, Any]
) -> tuple[bool, str]:
    tags = params.get("tags") or []
    if not isinstance(tags, list) or not tags:
        return False, "no tags provided"
    evidence = dict(finding.evidence or {})
    existing = list(evidence.get("tags") or [])
    for t in tags:
        if t not in existing:
            existing.append(str(t))
    evidence["tags"] = existing
    finding.evidence = evidence
    return True, f"tagged {tags}"


def _act_set_status(
    session: Session, org: Organization, finding: Finding, params: dict[str, Any]
) -> tuple[bool, str]:
    raw = params.get("status")
    try:
        new_status = FindingStatus(str(raw))
    except ValueError:
        return False, f"invalid status {raw!r}"
    finding.status = new_status
    return True, f"status set to {new_status.value}"


def _act_assign(
    session: Session, org: Organization, finding: Finding, params: dict[str, Any]
) -> tuple[bool, str]:
    assignee = params.get("assignee")
    if not assignee:
        return False, "no assignee provided"
    finding.assignee = str(assignee)
    return True, f"assigned to {assignee}"


_ACTIONS = {
    "quarantine": _act_quarantine,
    "notify_connectors": _act_notify,
    "forward_siem": _act_forward,
    "tag": _act_tag,
    "set_status": _act_set_status,
    "assign": _act_assign,
}


def _run_action(
    session: Session, org: Organization, finding: Finding, action: dict[str, Any]
) -> dict[str, Any]:
    atype = str(action.get("type", ""))
    fn = _ACTIONS.get(atype)
    if fn is None:
        return {"type": atype, "ok": False, "detail": f"unknown action {atype!r}"}
    params = action.get("params") or {}
    try:
        ok, detail = fn(session, org, finding, params)
    except Exception as exc:  # actions must never wedge the detection run
        return {"type": atype, "ok": False, "detail": f"error: {exc}"}
    return {"type": atype, "ok": ok, "detail": detail}


def run_playbooks(
    session: Session, org: Organization, finding: Finding
) -> list[PlaybookExecution]:
    """Evaluate enabled playbooks against a finding and run matching actions.
    Returns the executions recorded (one per fired playbook)."""
    playbooks = list(
        session.execute(
            select(ResponsePlaybook)
            .where(
                ResponsePlaybook.organization_id == org.id,
                ResponsePlaybook.enabled.is_(True),
            )
            .order_by(
                ResponsePlaybook.priority.asc(), ResponsePlaybook.created_at.asc()
            )
        ).scalars()
    )

    executions: list[PlaybookExecution] = []
    for playbook in playbooks:
        if not matches(playbook, finding):
            continue
        results = [
            _run_action(session, org, finding, action)
            for action in (playbook.actions or [])
        ]
        execution = PlaybookExecution(
            organization_id=org.id,
            playbook_id=playbook.id,
            finding_id=finding.id,
            results=results,
        )
        session.add(execution)
        executions.append(execution)
        if playbook.stop_on_match:
            break

    if executions:
        session.flush()
    return executions


__all__ = ["matches", "run_playbooks"]
