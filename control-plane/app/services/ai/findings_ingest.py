"""Ingest AI-discovered security findings and score them.

Two producers feed one pipeline:

* **report_observation** — an agent (or any AI) flags something it noticed,
  even incidentally (`POST /findings/report`).
* **run_ai_sweep** — Praetor's AI proactively hunts over recent activity and
  surfaces findings nobody asked for (scheduled).

Both are scored by the multi-agent triage panel (severity / impact / fidelity),
normalized into the shared `Finding` table (deduped), and — for confident
CRITICAL findings — routed into the existing auto-quarantine response.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    OPEN_FINDING_STATUSES,
    Finding,
    FindingSeverity,
    FindingSource,
    Organization,
)
from app.services.ai.agents import (
    FindingScore,
    sweep_activity,
    triage_finding,
)
from app.services.ai.config import build_pattern_summary
from app.services.ai.providers import LLMProvider
from app.services.quarantine import auto_quarantine_for_finding

_WS = re.compile(r"\s+")

# Confident CRITICAL findings can drive automated response; a speculative one
# should not quarantine a fleet.
_AUTO_RESPONSE_MIN_FIDELITY = 0.7


def _dedup_key(source: str, category: str, observation: str) -> str:
    norm = _WS.sub(" ", observation.strip().lower())[:512]
    digest = hashlib.sha1(norm.encode("utf-8")).hexdigest()[:16]
    return f"{source}:{category}:{digest}"


def store_scored_finding(
    session: Session,
    org: Organization,
    *,
    score: FindingScore,
    source: str,
    observation: str,
    agent_id: str | None = None,
    session_id: str | None = None,
    evidence: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> tuple[Finding, bool]:
    """Upsert a scored observation into the findings table. Returns
    (finding, created)."""
    now = now or datetime.now(UTC)
    dedup_key = _dedup_key(source, score.category, observation)
    ev: dict[str, Any] = {
        "observation": observation[:8000],
        "ai_rationale": score.rationale,
        "source": source,
        "actionable": score.actionable,
        **(evidence or {}),
    }

    existing = session.execute(
        select(Finding)
        .where(
            Finding.organization_id == org.id,
            Finding.dedup_key == dedup_key,
            Finding.status.in_(OPEN_FINDING_STATUSES),
        )
        .order_by(Finding.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if existing is not None:
        existing.count += 1
        existing.last_seen = now
        existing.severity = score.severity  # type: ignore[assignment]
        existing.impact = score.impact
        existing.fidelity = score.fidelity
        existing.evidence = ev
        return existing, False

    finding = Finding(
        organization_id=org.id,
        rule_id=source.replace("_", "-"),
        title=score.title,
        severity=score.severity,
        category=score.category,
        source=source,
        impact=score.impact,
        fidelity=score.fidelity,
        agent_id=agent_id,
        session_id=session_id,
        dedup_key=dedup_key,
        count=1,
        first_seen=now,
        last_seen=now,
        evidence=ev,
        atlas_technique=score.atlas_technique,
        owasp_llm=score.owasp_llm,
    )
    session.add(finding)
    session.flush()
    # Automated response only for confident CRITICAL findings.
    if (
        score.severity == FindingSeverity.CRITICAL
        and score.fidelity >= _AUTO_RESPONSE_MIN_FIDELITY
    ):
        auto_quarantine_for_finding(session, org, finding)
    return finding, True


def report_observation(
    session: Session,
    org: Organization,
    provider: LLMProvider | None,
    *,
    observation: str,
    agent_id: str | None = None,
    session_id: str | None = None,
    suggested_severity: str | None = None,
    context: str = "",
    evidence: dict[str, Any] | None = None,
) -> Finding:
    """Score (via AI if available, else a conservative fallback) and store an
    agent-reported observation."""
    if provider is not None:
        score = triage_finding(
            provider,
            observation=observation,
            context=context,
            suggested_severity=suggested_severity,
        )
    else:
        from app.services.ai.agents import _fallback_score

        score = _fallback_score(observation, suggested_severity)
    finding, _ = store_scored_finding(
        session,
        org,
        score=score,
        source=FindingSource.AGENT_REPORT.value,
        observation=observation,
        agent_id=agent_id,
        session_id=session_id,
        evidence=evidence,
    )
    return finding


def run_ai_sweep(
    session: Session, org: Organization, provider: LLMProvider
) -> dict[str, int]:
    """Proactively surface + score findings from recent activity."""
    digest = build_pattern_summary(session, org.id)
    scores = sweep_activity(provider, activity_digest=digest)
    created = updated = 0
    for score in scores:
        _, was_created = store_scored_finding(
            session,
            org,
            score=score,
            source=FindingSource.AI_SWEEP.value,
            observation=score.title,
            evidence={"digest_based": True},
        )
        if was_created:
            created += 1
        else:
            updated += 1
    session.flush()
    return {"surfaced": len(scores), "created": created, "updated": updated}


__all__ = ["report_observation", "run_ai_sweep", "store_scored_finding"]
