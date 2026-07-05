"""Detection engine: correlate audit events into security findings.

Each detection rule scans a rolling window of audit events and emits
`FindingDraft`s; `run_detections` upserts them into the `findings` table
(dedup on the OPEN finding for the same entity). This is the SIEM core —
it turns the raw decision stream into analyst-facing, framework-mapped
findings. Rules are intentionally simple and explainable; heavier
behavioral analytics (UEBA baselines, sequence models) build on top.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Row, select
from sqlalchemy.orm import Session

from app.models import (
    OPEN_FINDING_STATUSES,
    AuditEvent,
    Finding,
    FindingCategory,
    FindingSeverity,
    Organization,
)
from app.services.quarantine import auto_quarantine_for_finding

# Tunables (would move to per-org config later).
DEFAULT_WINDOW_MINUTES = 60
BASELINE_DAYS = 7
REPEATED_DENIAL_THRESHOLD = 5
APPROVAL_ABUSE_THRESHOLD = 5

# Substrings that mark a policy id as an exfil / egress-abuse denial, used to
# correlate injection -> exfil kill-chains.
_EXFIL_MARKERS = (
    "exfil",
    "metadata",
    "private-key",
    "rfc1918",
    "localhost",
    "onion",
    "pastebin",
    "webhook",
    "credential",
)


def _naive_utc(value: datetime) -> datetime:
    """Match the stored (SQLite-naive-UTC) audit timestamp form."""
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _is_exfil_policy(policy_id: str | None) -> bool:
    if not policy_id:
        return False
    pid = policy_id.lower()
    return any(marker in pid for marker in _EXFIL_MARKERS)


@dataclass
class FindingDraft:
    rule_id: str
    title: str
    severity: FindingSeverity
    category: FindingCategory
    dedup_key: str
    count: int
    agent_id: str | None = None
    session_id: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    atlas_technique: str | None = None
    owasp_llm: str | None = None


# One lightweight projection of the events a run needs (no full ORM hydration).
_EventRow = Row[Any]


def _window_events(session: Session, org_id: str, since: datetime) -> list[_EventRow]:
    stmt = (
        select(
            AuditEvent.id,
            AuditEvent.agent_id,
            AuditEvent.session_id,
            AuditEvent.tool_name,
            AuditEvent.decision,
            AuditEvent.matched_policy_id,
        )
        .where(
            AuditEvent.organization_id == org_id,
            AuditEvent.timestamp >= since,
        )
        .order_by(AuditEvent.timestamp.asc())
        .limit(20_000)  # bound worst-case memory
    )
    return list(session.execute(stmt).all())


def _detect_prompt_injection(rows: list[_EventRow]) -> list[FindingDraft]:
    by_session: dict[str, list[_EventRow]] = defaultdict(list)
    for r in rows:
        if (r.matched_policy_id or "").startswith("pi-") and r.decision in (
            "deny",
            "require_approval",
        ):
            by_session[r.session_id].append(r)
    drafts = []
    for session_id, evs in by_session.items():
        agent_id = evs[0].agent_id
        drafts.append(
            FindingDraft(
                rule_id="prompt-injection-detected",
                title=f"Prompt-injection attempt in session {session_id}",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.PROMPT_INJECTION,
                dedup_key=f"prompt-injection:{session_id}",
                count=len(evs),
                agent_id=agent_id,
                session_id=session_id,
                evidence={
                    "event_ids": [e.id for e in evs][:50],
                    "policies": sorted({e.matched_policy_id for e in evs if e.matched_policy_id}),
                },
                atlas_technique="AML.T0051",  # LLM Prompt Injection
                owasp_llm="LLM01",
            )
        )
    return drafts


def _detect_repeated_denials(rows: list[_EventRow]) -> list[FindingDraft]:
    by_agent: dict[str, list[_EventRow]] = defaultdict(list)
    for r in rows:
        if r.decision == "deny":
            by_agent[r.agent_id].append(r)
    drafts = []
    for agent_id, evs in by_agent.items():
        if len(evs) < REPEATED_DENIAL_THRESHOLD:
            continue
        drafts.append(
            FindingDraft(
                rule_id="repeated-denials",
                title=f"{len(evs)} denied tool calls from agent {agent_id}",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.POLICY_VIOLATION,
                dedup_key=f"repeated-denials:{agent_id}",
                count=len(evs),
                agent_id=agent_id,
                evidence={
                    "event_ids": [e.id for e in evs][:50],
                    "tools": sorted({e.tool_name for e in evs}),
                },
                atlas_technique="AML.T0050",  # Exploit Public-Facing Application (agent)
            )
        )
    return drafts


def _detect_injection_exfil_killchain(rows: list[_EventRow]) -> list[FindingDraft]:
    by_session: dict[str, list[_EventRow]] = defaultdict(list)
    for r in rows:
        by_session[r.session_id].append(r)
    drafts = []
    for session_id, evs in by_session.items():
        has_injection = any(
            (e.matched_policy_id or "").startswith("pi-") for e in evs
        )
        exfil = [e for e in evs if _is_exfil_policy(e.matched_policy_id)]
        if has_injection and exfil:
            drafts.append(
                FindingDraft(
                    rule_id="injection-exfil-killchain",
                    title=(
                        f"Injection followed by exfil attempt in session {session_id}"
                    ),
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.DATA_EXFIL,
                    dedup_key=f"injection-exfil:{session_id}",
                    count=len(exfil),
                    agent_id=evs[0].agent_id,
                    session_id=session_id,
                    evidence={
                        "exfil_event_ids": [e.id for e in exfil][:50],
                        "exfil_policies": sorted(
                            {e.matched_policy_id for e in exfil if e.matched_policy_id}
                        ),
                    },
                    atlas_technique="AML.T0024",  # Exfiltration via ML Inference API
                    owasp_llm="LLM02",
                )
            )
    return drafts


def _detect_approval_abuse(rows: list[_EventRow]) -> list[FindingDraft]:
    by_session: dict[str, list[_EventRow]] = defaultdict(list)
    for r in rows:
        if r.decision == "require_approval":
            by_session[r.session_id].append(r)
    drafts = []
    for session_id, evs in by_session.items():
        if len(evs) < APPROVAL_ABUSE_THRESHOLD:
            continue
        drafts.append(
            FindingDraft(
                rule_id="approval-abuse",
                title=(
                    f"{len(evs)} approval-gated calls in session {session_id} "
                    "(possible probing)"
                ),
                severity=FindingSeverity.LOW,
                category=FindingCategory.APPROVAL_ABUSE,
                dedup_key=f"approval-abuse:{session_id}",
                count=len(evs),
                agent_id=evs[0].agent_id,
                session_id=session_id,
                evidence={"event_ids": [e.id for e in evs][:50]},
            )
        )
    return drafts


def _detect_new_tool_anomaly(
    session: Session,
    org_id: str,
    rows: list[_EventRow],
    baseline_since: datetime,
    window_since: datetime,
) -> list[FindingDraft]:
    """UEBA-lite: an (agent, tool) pair seen in the window but not in the
    preceding baseline window [baseline_since, window_since) is anomalous."""
    window_pairs: set[tuple[str, str]] = {(r.agent_id, r.tool_name) for r in rows}
    if not window_pairs:
        return []
    known = set(
        session.execute(
            select(AuditEvent.agent_id, AuditEvent.tool_name)
            .where(
                AuditEvent.organization_id == org_id,
                AuditEvent.timestamp >= baseline_since,
                AuditEvent.timestamp < window_since,
            )
            .distinct()
        ).all()
    )
    known_pairs = {(a, t) for a, t in known}
    drafts = []
    for agent_id, tool_name in sorted(window_pairs - known_pairs):
        drafts.append(
            FindingDraft(
                rule_id="new-tool-anomaly",
                title=f"Agent {agent_id} used a new tool: {tool_name}",
                severity=FindingSeverity.INFO,
                category=FindingCategory.ANOMALY,
                dedup_key=f"new-tool:{agent_id}:{tool_name}",
                count=1,
                agent_id=agent_id,
                evidence={"tool_name": tool_name, "baseline_days": BASELINE_DAYS},
                atlas_technique="AML.T0040",  # ML Model Inference API Access (novel use)
            )
        )
    return drafts


def _upsert_finding(
    session: Session, org_id: str, draft: FindingDraft, now: datetime
) -> tuple[Finding, bool]:
    """Insert the draft, or update the live finding for the same entity.
    Returns (finding, created)."""
    existing = session.execute(
        select(Finding)
        .where(
            Finding.organization_id == org_id,
            Finding.dedup_key == draft.dedup_key,
            Finding.status.in_(OPEN_FINDING_STATUSES),
        )
        .order_by(Finding.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if existing is not None:
        existing.count = draft.count
        existing.last_seen = now
        existing.evidence = draft.evidence
        existing.severity = draft.severity
        existing.title = draft.title
        return existing, False
    finding = Finding(
        organization_id=org_id,
        rule_id=draft.rule_id,
        title=draft.title,
        severity=draft.severity,
        category=draft.category,
        agent_id=draft.agent_id,
        session_id=draft.session_id,
        dedup_key=draft.dedup_key,
        count=draft.count,
        first_seen=now,
        last_seen=now,
        evidence=draft.evidence,
        atlas_technique=draft.atlas_technique,
        owasp_llm=draft.owasp_llm,
    )
    session.add(finding)
    return finding, True


def run_detections(
    session: Session,
    *,
    org_id: str,
    now: datetime | None = None,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> dict[str, int]:
    """Run every detection rule for one org over the rolling window and
    upsert findings. Returns {created, updated}."""
    now = now or datetime.now(UTC)
    since = _naive_utc(now - timedelta(minutes=window_minutes))
    baseline_since = _naive_utc(now - timedelta(days=BASELINE_DAYS))
    rows = _window_events(session, org_id, since)

    drafts: list[FindingDraft] = []
    drafts += _detect_prompt_injection(rows)
    drafts += _detect_repeated_denials(rows)
    drafts += _detect_injection_exfil_killchain(rows)
    drafts += _detect_approval_abuse(rows)
    drafts += _detect_new_tool_anomaly(session, org_id, rows, baseline_since, since)

    created = updated = 0
    new_findings: list[Finding] = []
    for draft in drafts:
        finding, was_created = _upsert_finding(session, org_id, draft, now)
        if was_created:
            created += 1
            new_findings.append(finding)
        else:
            updated += 1
    session.flush()  # assign ids before auto-response references them

    # EDR auto-response: isolate the entity behind each new CRITICAL finding.
    quarantined = 0
    org = session.get(Organization, org_id)
    if org is not None:
        for finding in new_findings:
            if auto_quarantine_for_finding(session, org, finding) is not None:
                quarantined += 1
    session.flush()
    return {"created": created, "updated": updated, "quarantined": quarantined}


__all__ = ["FindingDraft", "run_detections"]
