"""Security findings: list, inspect, triage, and run detections on demand.

Findings are produced by the detection engine (scheduled via Celery beat);
these endpoints are the analyst surface — the SIEM/EDR console's backend.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingSource,
    FindingStatus,
    Organization,
    Role,
    risk_score,
)
from app.schemas import FindingOut, FindingReportIn, FindingUpdateIn
from app.services.access_log import access_log
from app.services.ai.budget import is_over_budget, metered
from app.services.ai.config import ai_available, org_llm_config
from app.services.ai.findings_ingest import report_observation, run_ai_sweep
from app.services.ai.providers import LLMError, get_provider
from app.services.detections import run_detections
from app.services.ratelimit import rate_limit
from app.settings import Settings, get_settings
from app.workers.tasks import dispatch_finding_task

router = APIRouter(tags=["findings"])

_TERMINAL = (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE)


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _al: None = Depends(access_log("findings")),
    status_filter: Annotated[FindingStatus | None, Query(alias="status")] = None,
    severity: FindingSeverity | None = None,
    category: FindingCategory | None = None,
    source: FindingSource | None = None,
    agent_id: str | None = None,
    sort: Literal["last_seen", "risk"] = "last_seen",
    include_low_fidelity: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Finding]:
    stmt = select(Finding).where(Finding.organization_id == org.id)
    if status_filter:
        stmt = stmt.where(Finding.status == status_filter)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if category:
        stmt = stmt.where(Finding.category == category)
    if source:
        stmt = stmt.where(Finding.source == source.value)
    if agent_id:
        stmt = stmt.where(Finding.agent_id == agent_id)
    # Hide speculative (low-fidelity) findings by default; kept, not dropped.
    if not include_low_fidelity:
        stmt = stmt.where(Finding.fidelity >= org.finding_fidelity_threshold)

    if sort == "risk":
        # risk_score is derived (severity x impact x fidelity), so rank in
        # Python over a bounded window, then page.
        rows = list(
            session.execute(
                stmt.order_by(Finding.last_seen.desc()).limit(500)
            ).scalars()
        )
        rows.sort(
            key=lambda f: risk_score(f.severity, f.impact, f.fidelity),
            reverse=True,
        )
        return rows[offset : offset + limit]

    stmt = stmt.order_by(Finding.last_seen.desc()).limit(limit).offset(offset)
    return list(session.execute(stmt).scalars().all())


@router.post("/findings/report", response_model=FindingOut, status_code=201)
def report_finding(
    body: FindingReportIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _p: Principal = Depends(require_role(Role.ANALYST)),
    _rl: None = Depends(rate_limit("ingest")),
) -> Finding:
    """Ingest a security observation an agent/AI found — even incidentally.

    Scored by the AI triage panel (severity/impact/fidelity) when the org has
    opted in; otherwise stored with the suggested severity and flagged
    unscored. Deduplicated into the findings dashboard."""
    provider = None
    # Score with AI when enabled and under budget; otherwise store unscored
    # (an over-budget or unavailable model must not block ingestion).
    if ai_available(org) and not is_over_budget(session, org, settings):
        config = org_llm_config(org, settings)
        if config is not None:
            try:
                provider = metered(get_provider(config), session, org, settings)
            except LLMError:
                provider = None  # fall back to unscored storage
    finding = report_observation(
        session,
        org,
        provider,
        observation=body.observation,
        agent_id=body.agent_id,
        session_id=body.session_id,
        suggested_severity=(
            body.suggested_severity.value if body.suggested_severity else None
        ),
        context=body.context,
        evidence=body.evidence or None,
    )
    # Commit so the worker (own session) sees the finding, then dispatch to the
    # SIEM/webhook + typed connectors off the request path. This is the ambient
    # path: an agent-reported finding notifies immediately instead of waiting
    # for the next detection cycle. Eager mode (tests/dev) runs it inline.
    session.commit()
    dispatch_finding_task.delay(finding.id)
    session.refresh(finding)
    return finding


@router.post("/findings/sweep", response_model=dict[str, int])
def sweep_findings(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _p: Principal = Depends(require_role(Role.ANALYST)),
    _rl: None = Depends(rate_limit("ai")),
) -> dict[str, int]:
    """Proactively hunt findings the rules missed, over recent activity.

    Requires the AI service to be enabled (BYOK)."""
    if not ai_available(org):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="AI advisory is not enabled; configure it via PATCH /ai/config",
        )
    if is_over_budget(session, org, settings):
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            detail="monthly AI budget exceeded for this organization",
        )
    config = org_llm_config(org, settings)
    assert config is not None
    try:
        provider = metered(get_provider(config), session, org, settings)
    except LLMError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, detail=str(exc)
        ) from exc
    return run_ai_sweep(session, org, provider)


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> Finding:
    return get_owned(session, Finding, finding_id, org, detail="finding not found")


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: str,
    body: FindingUpdateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> Finding:
    """Triage a finding: change status, assign, or annotate."""
    finding = get_owned(
        session, Finding, finding_id, org, detail="finding not found"
    )
    fields = body.model_dump(exclude_unset=True)
    if "assignee" in fields:
        finding.assignee = fields["assignee"]
    if "note" in fields:
        finding.note = fields["note"]
    if "status" in fields and fields["status"] is not None:
        new_status = fields["status"]
        finding.status = new_status
        if new_status in _TERMINAL:
            finding.resolved_at = datetime.now(UTC)
            finding.resolved_by = fields.get("resolved_by") or finding.resolved_by
        else:
            finding.resolved_at = None
            finding.resolved_by = None
    session.flush()
    return finding


@router.post("/findings/run", response_model=dict[str, Any])
def run_now(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
    window_minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
) -> dict[str, Any]:
    """Run the detection engine for this org immediately (returns created/updated)."""
    return run_detections(session, org_id=org.id, window_minutes=window_minutes)
