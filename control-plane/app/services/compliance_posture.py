"""AI compliance posture: map Praetor controls to AI governance frameworks.

Unlike the period-based evidence report (``app.services.report``), this is a
*live posture assessment*: it snapshots the org's current control configuration
(policies, detections, auto-response, redaction, SOAR, threat intel, cost
controls, plus always-on platform guarantees like the tamper-evident audit log
and the kill-switch) and grades each framework control as satisfied / partial /
gap, with concrete remediation for what's missing.

Frameworks covered: NIST AI RMF 1.0, EU AI Act (high-risk obligations), and the
OWASP Top 10 for LLM Applications. The catalog is static; posture is computed
on demand — nothing is persisted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    AgentBaseline,
    DetectionRule,
    Finding,
    FindingSeverity,
    FindingStatus,
    NotificationConnector,
    Organization,
    PolicyBundle,
    Project,
    ResponsePlaybook,
    ThreatFeed,
)

# --- signals ----------------------------------------------------------------
# Human label + remediation for each signal a control can require. Platform
# guarantees (audit trail, tamper-evident chain, kill-switch, human approval,
# detection engine) are always present — Praetor provides them unconditionally.
_SIGNAL_META: dict[str, tuple[str, str]] = {
    "policy_enforcement": (
        "Deterministic policy enforcement",
        "Publish at least one policy bundle so agent tool calls are governed.",
    ),
    "custom_detections": (
        "Custom detection rules",
        "Add detection rules to surface org-specific threats.",
    ),
    "auto_quarantine": (
        "Automated EDR response",
        "Enable auto-quarantine so critical findings isolate the entity.",
    ),
    "pii_redaction": (
        "PII redaction",
        "Enable PII redaction so sensitive data is masked on ingest.",
    ),
    "incident_notification": (
        "Incident notification / SIEM forwarding",
        "Configure a notification connector or finding webhook.",
    ),
    "soar_playbooks": (
        "SOAR response playbooks",
        "Create a response playbook to automate finding-driven response.",
    ),
    "cost_controls": (
        "Spend / consumption controls",
        "Set a monthly cost budget or per-agent quota.",
    ),
    "threat_intel": (
        "Threat-intelligence feeds",
        "Connect a threat-intel feed to enrich detection.",
    ),
    "behavioral_baselines": (
        "Behavioral baselining (UEBA)",
        "Let agent baselines accrue so anomalies can be detected.",
    ),
    # Always-on platform guarantees.
    "audit_trail": ("Immutable audit trail", ""),
    "tamper_evident_audit": ("Tamper-evident audit chain", ""),
    "kill_switch": ("Global kill-switch", ""),
    "human_approval": ("Human-in-the-loop approvals", ""),
    "detection_engine": ("Continuous detection engine", ""),
}


@dataclass(frozen=True)
class PostureSignals:
    # Configuration-dependent controls.
    policy_enforcement: bool
    custom_detections: bool
    auto_quarantine: bool
    pii_redaction: bool
    incident_notification: bool
    soar_playbooks: bool
    cost_controls: bool
    threat_intel: bool
    behavioral_baselines: bool
    open_critical_findings: int
    # Always-on platform guarantees.
    audit_trail: bool = True
    tamper_evident_audit: bool = True
    kill_switch: bool = True
    human_approval: bool = True
    detection_engine: bool = True

    def has(self, key: str) -> bool:
        return bool(getattr(self, key))


def _exists(session: Session, stmt: Any) -> bool:
    return session.execute(select(stmt.exists())).scalar() or False


def collect_signals(session: Session, org: Organization) -> PostureSignals:
    """Snapshot the org's current control posture from live state."""
    policy = _exists(
        session,
        select(PolicyBundle.id)
        .join(Project, PolicyBundle.project_id == Project.id)
        .where(Project.organization_id == org.id),
    )
    detections = _exists(
        session,
        select(DetectionRule.id).where(
            DetectionRule.organization_id == org.id,
            DetectionRule.enabled.is_(True),
        ),
    )
    connectors = _exists(
        session,
        select(NotificationConnector.id).where(
            NotificationConnector.organization_id == org.id,
            NotificationConnector.enabled.is_(True),
        ),
    )
    playbooks = _exists(
        session,
        select(ResponsePlaybook.id).where(
            ResponsePlaybook.organization_id == org.id,
            ResponsePlaybook.enabled.is_(True),
        ),
    )
    feeds = _exists(
        session,
        select(ThreatFeed.id).where(ThreatFeed.organization_id == org.id),
    )
    baselines = _exists(
        session,
        select(AgentBaseline.id).where(AgentBaseline.organization_id == org.id),
    )
    open_criticals = int(
        session.execute(
            select(func.count(Finding.id)).where(
                Finding.organization_id == org.id,
                Finding.severity == FindingSeverity.CRITICAL,
                Finding.status.in_(
                    (FindingStatus.OPEN, FindingStatus.TRIAGING)
                ),
            )
        ).scalar_one()
    )

    return PostureSignals(
        policy_enforcement=policy,
        custom_detections=detections,
        auto_quarantine=bool(org.auto_quarantine),
        pii_redaction=bool(org.pii_redaction_enabled),
        incident_notification=connectors or bool(org.finding_webhook_url),
        soar_playbooks=playbooks,
        cost_controls=(
            org.monthly_cost_budget_usd is not None
            or bool(org.enforce_cost_budget)
            or org.agent_cost_quota_usd is not None
        ),
        threat_intel=feeds,
        behavioral_baselines=baselines,
        open_critical_findings=open_criticals,
    )


# --- framework catalog ------------------------------------------------------
@dataclass(frozen=True)
class Control:
    id: str
    title: str
    description: str
    signals: tuple[str, ...]


@dataclass(frozen=True)
class Framework:
    key: str
    title: str
    controls: tuple[Control, ...]


_FRAMEWORKS: dict[str, Framework] = {
    "nist_ai_rmf": Framework(
        key="nist_ai_rmf",
        title="NIST AI Risk Management Framework 1.0",
        controls=(
            Control(
                "GOVERN-1.1",
                "Policies, processes & procedures",
                "Documented, enforced policies govern AI system behavior.",
                ("policy_enforcement", "audit_trail"),
            ),
            Control(
                "GOVERN-4.1",
                "Accountability & auditability",
                "Decisions are logged to a tamper-evident, accountable record.",
                ("audit_trail", "tamper_evident_audit"),
            ),
            Control(
                "MAP-5.1",
                "Threat & impact identification",
                "AI-specific threats are identified and enriched.",
                ("custom_detections", "threat_intel"),
            ),
            Control(
                "MEASURE-2.6",
                "AI system monitoring",
                "Deployed AI behavior is continuously monitored for drift.",
                ("detection_engine", "behavioral_baselines"),
            ),
            Control(
                "MEASURE-2.7",
                "Security & resilience monitoring",
                "Security-relevant events are detected and measured.",
                ("custom_detections", "threat_intel"),
            ),
            Control(
                "MANAGE-2.1",
                "Response & recovery plans",
                "Automated response plans exist for identified risks.",
                ("soar_playbooks", "auto_quarantine"),
            ),
            Control(
                "MANAGE-2.3",
                "Incident response & containment",
                "Incidents can be contained and stakeholders notified.",
                ("kill_switch", "incident_notification"),
            ),
            Control(
                "MANAGE-4.1",
                "Post-deployment monitoring & response",
                "Ongoing monitoring feeds an automated response loop.",
                ("detection_engine", "soar_playbooks"),
            ),
        ),
    ),
    "eu_ai_act": Framework(
        key="eu_ai_act",
        title="EU AI Act — high-risk system obligations",
        controls=(
            Control(
                "Article-9",
                "Risk management system",
                "A continuous risk management system governs the AI system.",
                ("policy_enforcement", "custom_detections"),
            ),
            Control(
                "Article-10",
                "Data & data governance",
                "Sensitive data is governed and minimized.",
                ("pii_redaction",),
            ),
            Control(
                "Article-12",
                "Record-keeping (logging)",
                "Automatic, tamper-evident logging of system events.",
                ("audit_trail", "tamper_evident_audit"),
            ),
            Control(
                "Article-14",
                "Human oversight",
                "Humans can oversee and intervene, including a stop control.",
                ("human_approval", "kill_switch"),
            ),
            Control(
                "Article-15",
                "Accuracy, robustness & cybersecurity",
                "The system is monitored for security and anomalous behavior.",
                ("custom_detections", "threat_intel", "behavioral_baselines"),
            ),
            Control(
                "Article-26",
                "Deployer monitoring obligations",
                "Deployers monitor operation and act on serious incidents.",
                ("detection_engine", "incident_notification", "soar_playbooks"),
            ),
        ),
    ),
    "owasp_llm": Framework(
        key="owasp_llm",
        title="OWASP Top 10 for LLM Applications",
        controls=(
            Control(
                "LLM01",
                "Prompt Injection",
                "Injection attempts are governed by policy and detected.",
                ("policy_enforcement", "custom_detections"),
            ),
            Control(
                "LLM02",
                "Sensitive Information Disclosure",
                "Sensitive data is redacted and exfil is detected.",
                ("pii_redaction", "detection_engine"),
            ),
            Control(
                "LLM04",
                "Data & Model Poisoning",
                "Threat intelligence guards against poisoned inputs.",
                ("threat_intel",),
            ),
            Control(
                "LLM06",
                "Excessive Agency",
                "Agent authority is bounded by policy, approvals & a kill-switch.",
                ("policy_enforcement", "human_approval", "kill_switch"),
            ),
            Control(
                "LLM07",
                "System Prompt Leakage",
                "Leakage attempts are detected by the engine.",
                ("detection_engine", "custom_detections"),
            ),
            Control(
                "LLM10",
                "Unbounded Consumption",
                "Spend and consumption are capped.",
                ("cost_controls",),
            ),
        ),
    ),
}

_STATUS_SCORE = {"satisfied": 1.0, "partial": 0.5, "gap": 0.0}


def list_frameworks() -> list[dict[str, Any]]:
    """The static catalog: frameworks and their controls (no org state)."""
    return [
        {
            "key": fw.key,
            "title": fw.title,
            "controls": [
                {
                    "id": c.id,
                    "title": c.title,
                    "description": c.description,
                    "signals": [
                        {"key": s, "label": _SIGNAL_META[s][0]} for s in c.signals
                    ],
                }
                for c in fw.controls
            ],
        }
        for fw in _FRAMEWORKS.values()
    ]


def _assess_control(control: Control, signals: PostureSignals) -> dict[str, Any]:
    present = [s for s in control.signals if signals.has(s)]
    missing = [s for s in control.signals if not signals.has(s)]
    if not missing:
        status = "satisfied"
    elif present:
        status = "partial"
    else:
        status = "gap"
    remediation = [
        _SIGNAL_META[s][1] for s in missing if _SIGNAL_META[s][1]
    ]
    return {
        "id": control.id,
        "title": control.title,
        "description": control.description,
        "status": status,
        "present_signals": present,
        "missing_signals": missing,
        "remediation": remediation,
    }


def compute_posture(
    session: Session, org: Organization, framework: str
) -> dict[str, Any]:
    """Assess one framework against the org's live control posture.

    Raises KeyError if ``framework`` is unknown.
    """
    fw = _FRAMEWORKS[framework]
    signals = collect_signals(session, org)
    controls = [_assess_control(c, signals) for c in fw.controls]

    counts = {"satisfied": 0, "partial": 0, "gap": 0}
    score = 0.0
    for c in controls:
        counts[c["status"]] += 1
        score += _STATUS_SCORE[c["status"]]
    total = len(controls)
    coverage = round(score / total, 3) if total else 0.0

    return {
        "framework": fw.key,
        "title": fw.title,
        "generated_at": datetime.now(UTC).isoformat(),
        "coverage": coverage,
        "controls_total": total,
        "controls_satisfied": counts["satisfied"],
        "controls_partial": counts["partial"],
        "controls_gap": counts["gap"],
        "open_critical_findings": signals.open_critical_findings,
        "controls": controls,
    }


def posture_overview(session: Session, org: Organization) -> dict[str, Any]:
    """Coverage summary across every framework (for a compliance dashboard).

    Computes signals once and grades all frameworks against that single
    snapshot — cheaper and more consistent than calling compute_posture per
    framework.
    """
    signals = collect_signals(session, org)
    frameworks = []
    for fw in _FRAMEWORKS.values():
        counts = {"satisfied": 0, "partial": 0, "gap": 0}
        score = 0.0
        for control in fw.controls:
            status = _assess_control(control, signals)["status"]
            counts[status] += 1
            score += _STATUS_SCORE[status]
        total = len(fw.controls)
        frameworks.append(
            {
                "framework": fw.key,
                "title": fw.title,
                "coverage": round(score / total, 3) if total else 0.0,
                "controls_total": total,
                "controls_satisfied": counts["satisfied"],
                "controls_partial": counts["partial"],
                "controls_gap": counts["gap"],
            }
        )
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "open_critical_findings": signals.open_critical_findings,
        "frameworks": frameworks,
    }


def known_framework(framework: str) -> bool:
    return framework in _FRAMEWORKS


__all__ = [
    "PostureSignals",
    "collect_signals",
    "compute_posture",
    "known_framework",
    "list_frameworks",
    "posture_overview",
]
