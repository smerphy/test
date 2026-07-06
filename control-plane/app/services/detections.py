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
    DetectionRule,
    Finding,
    FindingCategory,
    FindingSeverity,
    IndicatorType,
    Organization,
)
from app.services.quarantine import auto_quarantine_for_finding
from app.services.threat_intel import build_index, match_activity, severity_rank

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


def _event_matches(row: _EventRow, spec: dict[str, Any]) -> bool:
    pid = row.matched_policy_id or ""
    prefix = spec.get("matched_policy_prefix")
    contains = spec.get("matched_policy_contains")
    return (
        (not spec.get("decision") or row.decision == spec["decision"])
        and (not prefix or pid.startswith(prefix))
        and (not contains or contains in pid)
        and (not spec.get("tool_name") or row.tool_name == spec["tool_name"])
    )


def _detect_custom_rules(
    session: Session, org_id: str, rows: list[_EventRow]
) -> list[FindingDraft]:
    """Evaluate the org's enabled detection-as-code rules over the window."""
    rules = list(
        session.execute(
            select(DetectionRule).where(
                DetectionRule.organization_id == org_id,
                DetectionRule.enabled.is_(True),
            )
        ).scalars()
    )
    drafts: list[FindingDraft] = []
    for rule in rules:
        spec = rule.spec or {}
        group_by = spec.get("group_by", "session")
        threshold = int(spec.get("threshold", 1))
        groups: dict[str, list[_EventRow]] = defaultdict(list)
        for r in rows:
            if not _event_matches(r, spec):
                continue
            key = r.agent_id if group_by == "agent" else r.session_id
            groups[key].append(r)
        for key, evs in groups.items():
            if len(evs) < threshold:
                continue
            drafts.append(
                FindingDraft(
                    rule_id=rule.name,
                    title=f"{rule.name}: {len(evs)} matching events for {group_by}={key}",
                    severity=FindingSeverity(rule.severity),
                    category=FindingCategory(rule.category),
                    dedup_key=f"custom:{rule.id}:{key}",
                    count=len(evs),
                    agent_id=evs[0].agent_id,
                    session_id=None if group_by == "agent" else key,
                    evidence={"event_ids": [e.id for e in evs][:50]},
                    atlas_technique=rule.atlas_technique,
                    owasp_llm=rule.owasp_llm,
                )
            )
    return drafts


def _threat_intel_mapping(types: set[str]) -> tuple[str | None, str | None]:
    """Map the matched indicator types to an ATLAS technique + OWASP LLM id."""
    if types & {IndicatorType.PROMPT_SIGNATURE.value, IndicatorType.REGEX.value}:
        return "AML.T0051", "LLM01"  # LLM Prompt Injection
    if types & {
        IndicatorType.DOMAIN.value,
        IndicatorType.IP.value,
        IndicatorType.URL.value,
        IndicatorType.EMAIL.value,
    }:
        return "AML.T0024", "LLM02"  # Exfiltration / insecure output → egress
    # hash / package / tool_name → supply-chain / malicious tooling.
    return "AML.T0010", "LLM05"  # ML Supply Chain Compromise


def _detect_threat_intel(
    session: Session, org_id: str, since: datetime
) -> list[FindingDraft]:
    """Match window events against the org's active threat-intel indicators.

    Any tool call whose name or arguments contain a known-bad indicator
    (malicious domain/IP/URL/hash, malicious tool/package, or a
    prompt-injection signature) raises a threat-intel finding for its session.
    """
    index = build_index(session, org_id)
    if index.is_empty():
        return []

    rows = session.execute(
        select(
            AuditEvent.id,
            AuditEvent.agent_id,
            AuditEvent.session_id,
            AuditEvent.tool_name,
            AuditEvent.tool_arguments,
        )
        .where(
            AuditEvent.organization_id == org_id,
            AuditEvent.timestamp >= since,
        )
        .order_by(AuditEvent.timestamp.asc())
        .limit(5_000)
    ).all()

    @dataclass
    class _Acc:
        agent_id: str
        event_ids: list[str] = field(default_factory=list)
        indicators: dict[str, Any] = field(default_factory=dict)
        match_count: int = 0

    by_session: dict[str, _Acc] = {}
    for r in rows:
        hits = match_activity(index, r.tool_name, r.tool_arguments)
        if not hits:
            continue
        acc = by_session.setdefault(r.session_id, _Acc(agent_id=r.agent_id))
        acc.match_count += 1
        if len(acc.event_ids) < 50:
            acc.event_ids.append(r.id)
        for meta in hits:
            acc.indicators[meta.id] = meta

    drafts: list[FindingDraft] = []
    for session_id, acc in by_session.items():
        metas = list(acc.indicators.values())
        top = max(metas, key=lambda m: severity_rank(m.severity))
        types = {m.type for m in metas}
        atlas, owasp = _threat_intel_mapping(types)
        drafts.append(
            FindingDraft(
                rule_id="threat-intel-match",
                title=(
                    f"Threat-intel match in session {session_id}: "
                    f"{len(metas)} indicator(s)"
                ),
                severity=FindingSeverity(top.severity),
                category=FindingCategory.THREAT_INTEL,
                dedup_key=f"threat-intel:{session_id}",
                count=acc.match_count,
                agent_id=acc.agent_id,
                session_id=session_id,
                evidence={
                    "event_ids": acc.event_ids,
                    "indicators": [
                        {
                            "id": m.id,
                            "type": m.type,
                            "value": m.value,
                            "severity": m.severity,
                            "confidence": m.confidence,
                        }
                        for m in metas[:50]
                    ],
                },
                atlas_technique=atlas,
                owasp_llm=owasp,
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
) -> dict[str, Any]:
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
    drafts += _detect_custom_rules(session, org_id, rows)
    drafts += _detect_threat_intel(session, org_id, since)

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
    return {
        "created": created,
        "updated": updated,
        "quarantined": quarantined,
        "new_finding_ids": [f.id for f in new_findings],
    }


__all__ = ["FindingDraft", "run_detections"]
