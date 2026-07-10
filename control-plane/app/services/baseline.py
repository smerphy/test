"""UEBA: build per-agent behavioral baselines and detect drift.

``rebuild_baselines`` snapshots each agent's normal behavior (tool mix, decision
mix, breadth) over a training window into :class:`AgentBaseline`.
``detect_drift`` compares an agent's recent activity to its baseline and raises
findings for behavioral anomalies the rule-based detectors miss:

* **new tool** — the agent invoked a tool it has never used in its baseline;
* **denial spike** — the agent's recent denial rate is far above its baseline.

Findings dedupe per (agent, signal) so a persistent anomaly updates in place
rather than spamming. Behavioral signals get fidelity < 1 (they are
suggestive, not certain).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    OPEN_FINDING_STATUSES,
    AgentBaseline,
    AuditEvent,
    Finding,
    FindingCategory,
    FindingSource,
    Organization,
)

_MIN_RECENT_EVENTS = 5  # need enough recent signal to judge drift
_DENY_SPIKE_FACTOR = 3.0
_DENY_SPIKE_FLOOR = 0.3  # recent deny-rate must also clear this absolute floor
_DENY_SPIKE_MIN_DENIES = 3
_FIDELITY = 0.8


def _naive(ts: datetime) -> datetime:
    return ts.astimezone(UTC).replace(tzinfo=None) if ts.tzinfo else ts


def rebuild_baselines(
    session: Session,
    org_id: str,
    *,
    lookback_days: int = 30,
    now: datetime | None = None,
) -> dict[str, int]:
    """(Re)compute each agent's baseline from the training window. Upserts one
    baseline per agent. Returns {agents, events}."""
    now = now or datetime.now(UTC)
    start = now - timedelta(days=lookback_days)
    rows = session.execute(
        select(
            AuditEvent.agent_id,
            AuditEvent.tool_name,
            AuditEvent.decision,
            AuditEvent.session_id,
        ).where(
            AuditEvent.organization_id == org_id,
            AuditEvent.timestamp >= _naive(start),
        )
    ).all()

    tools: dict[str, Counter[str]] = defaultdict(Counter)
    decisions: dict[str, Counter[str]] = defaultdict(Counter)
    sessions: dict[str, set[str]] = defaultdict(set)
    totals: Counter[str] = Counter()
    for r in rows:
        tools[r.agent_id][r.tool_name] += 1
        decisions[r.agent_id][r.decision] += 1
        sessions[r.agent_id].add(r.session_id)
        totals[r.agent_id] += 1

    # Prefetch existing baselines for the org in one query, keyed by agent, so
    # the upsert loop doesn't SELECT per agent (N+1).
    existing_baselines = {
        b.agent_id: b
        for b in session.execute(
            select(AgentBaseline).where(
                AgentBaseline.organization_id == org_id
            )
        ).scalars()
    }
    for agent_id, total in totals.items():
        baseline = existing_baselines.get(agent_id)
        fields = dict(
            window_start=start,
            window_end=now,
            event_count=total,
            tool_counts=dict(tools[agent_id]),
            decision_counts=dict(decisions[agent_id]),
            distinct_tools=len(tools[agent_id]),
            distinct_sessions=len(sessions[agent_id]),
        )
        if baseline is None:
            session.add(
                AgentBaseline(
                    organization_id=org_id, agent_id=agent_id, **fields
                )
            )
        else:
            for k, v in fields.items():
                setattr(baseline, k, v)
    session.flush()
    return {"agents": len(totals), "events": int(sum(totals.values()))}


def _upsert_finding(
    session: Session,
    org_id: str,
    *,
    agent_id: str,
    signal: str,
    title: str,
    severity: str,
    evidence: dict[str, Any],
    now: datetime,
) -> bool:
    """Create or refresh a UEBA finding. Returns True if newly created."""
    dedup_key = f"ueba:{signal}:{agent_id}"
    existing = session.execute(
        select(Finding).where(
            Finding.organization_id == org_id,
            Finding.dedup_key == dedup_key,
            Finding.status.in_(OPEN_FINDING_STATUSES),
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.count += 1
        existing.last_seen = now
        existing.evidence = evidence
        return False
    session.add(
        Finding(
            organization_id=org_id,
            rule_id=f"ueba-{signal}",
            title=title,
            severity=severity,
            category=FindingCategory.ANOMALY.value,
            source=FindingSource.DETECTION_ENGINE.value,
            impact="moderate",
            fidelity=_FIDELITY,
            agent_id=agent_id,
            dedup_key=dedup_key,
            count=1,
            first_seen=now,
            last_seen=now,
            evidence=evidence,
        )
    )
    return True


def detect_drift(
    session: Session,
    org: Organization,
    *,
    recent_minutes: int = 60,
    now: datetime | None = None,
) -> dict[str, int]:
    """Compare each agent's recent activity to its baseline and raise findings
    for new-tool and denial-spike drift. Returns {agents, findings}."""
    now = now or datetime.now(UTC)
    since = _naive(now - timedelta(minutes=recent_minutes))
    baselines = list(
        session.execute(
            select(AgentBaseline).where(AgentBaseline.organization_id == org.id)
        ).scalars()
    )

    # Load every agent's recent events in ONE query and bucket by agent, rather
    # than issuing a separate SELECT per baseline (N+1 on a periodic sweep).
    recent_by_agent: dict[str, list[Any]] = defaultdict(list)
    for row in session.execute(
        select(
            AuditEvent.agent_id, AuditEvent.tool_name, AuditEvent.decision
        ).where(
            AuditEvent.organization_id == org.id,
            AuditEvent.timestamp >= since,
        )
    ):
        recent_by_agent[row.agent_id].append(row)

    findings = 0
    checked = 0
    for baseline in baselines:
        recent = recent_by_agent.get(baseline.agent_id, [])
        if len(recent) < _MIN_RECENT_EVENTS:
            continue
        checked += 1

        known_tools = set(baseline.tool_counts or {})
        recent_tools = {r.tool_name for r in recent}
        new_tools = sorted(recent_tools - known_tools)
        if new_tools:
            findings += _upsert_finding(
                session, org.id,
                agent_id=baseline.agent_id, signal="new-tool",
                title=(
                    f"Agent {baseline.agent_id} used {len(new_tools)} tool(s) "
                    "not seen in its baseline"
                ),
                severity="medium",
                evidence={"new_tools": new_tools, "recent_events": len(recent)},
                now=now,
            )

        recent_denies = sum(1 for r in recent if r.decision == "deny")
        recent_rate = recent_denies / len(recent)
        base_denies = int((baseline.decision_counts or {}).get("deny", 0))
        base_rate = base_denies / baseline.event_count if baseline.event_count else 0.0
        if (
            recent_denies >= _DENY_SPIKE_MIN_DENIES
            and recent_rate >= _DENY_SPIKE_FLOOR
            and recent_rate >= max(base_rate * _DENY_SPIKE_FACTOR, _DENY_SPIKE_FLOOR)
        ):
            findings += _upsert_finding(
                session, org.id,
                agent_id=baseline.agent_id, signal="deny-spike",
                title=(
                    f"Agent {baseline.agent_id} denial rate spiked to "
                    f"{recent_rate:.0%} (baseline {base_rate:.0%})"
                ),
                severity="high",
                evidence={
                    "recent_deny_rate": round(recent_rate, 3),
                    "baseline_deny_rate": round(base_rate, 3),
                    "recent_denies": recent_denies,
                    "recent_events": len(recent),
                },
                now=now,
            )

    session.flush()
    return {"agents": checked, "findings": findings}


__all__ = ["detect_drift", "rebuild_baselines"]
