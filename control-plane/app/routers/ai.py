"""AI-native advisory: opt-in config (BYOK), multi-agent action assessment,
and AI-proposed detection-rule review.

Every capability is gated on the org opting in and supplying its own provider
key — with no opt-in, these endpoints return 409 and no model is ever called.
The deterministic policy engine remains fully functional and authoritative;
the AI only advises, or (in ``enforce`` mode) tightens.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import (
    DetectionRule,
    Organization,
    Role,
    RuleSuggestion,
    SuggestionStatus,
)
from app.schemas import (
    AgentOpinionOut,
    AIConfigOut,
    AIConfigUpdateIn,
    AssessIn,
    AssessOut,
    DetectionRuleSpec,
    RuleSuggestionOut,
    SuggestionReviewIn,
)
from app.services.ai.agents import (
    ActionContext,
    assess_action,
    propose_rules,
    reconcile,
)
from app.services.ai.config import (
    ai_available,
    build_pattern_summary,
    org_llm_config,
)
from app.services.ai.providers import LLMError, get_provider
from app.services.egress import EgressBlocked, assert_safe_webhook_url
from app.settings import Settings, get_settings

router = APIRouter(tags=["ai"])


def _config_out(org: Organization) -> AIConfigOut:
    return AIConfigOut(
        ai_enabled=org.ai_enabled,
        ai_mode=org.ai_mode,
        ai_provider=org.ai_provider,
        ai_model=org.ai_model,
        ai_base_url=org.ai_base_url,
        ai_key_set=bool(org.ai_api_key),
    )


@router.get("/ai/config", response_model=AIConfigOut)
def get_config(
    org: Organization = Depends(current_org),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> AIConfigOut:
    return _config_out(org)


@router.patch("/ai/config", response_model=AIConfigOut)
def update_config(
    body: AIConfigUpdateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> AIConfigOut:
    fields = body.model_dump(exclude_unset=True)
    if fields.get("ai_base_url") and not settings.ai_allow_private_endpoints:
        try:
            assert_safe_webhook_url(fields["ai_base_url"])
        except EgressBlocked as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"ai_base_url rejected: {exc}",
            ) from exc
    for key in (
        "ai_enabled",
        "ai_mode",
        "ai_provider",
        "ai_model",
        "ai_base_url",
    ):
        if key in fields and fields[key] is not None:
            setattr(org, key, fields[key])
    if "ai_api_key" in fields:
        # Empty string clears the stored key; otherwise set it.
        org.ai_api_key = fields["ai_api_key"] or None
    session.flush()
    return _config_out(org)


def _require_ai(org: Organization) -> None:
    if not ai_available(org):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                "AI advisory is not enabled for this organization; opt in and "
                "configure a provider, model, and API key via PATCH /ai/config"
            ),
        )


@router.post("/ai/assess", response_model=AssessOut)
def assess(
    body: AssessIn,
    org: Organization = Depends(current_org),
    settings: Settings = Depends(get_settings),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> AssessOut:
    _require_ai(org)
    config = org_llm_config(org, settings)
    assert config is not None  # guaranteed by _require_ai
    try:
        provider = get_provider(config)
    except LLMError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, detail=str(exc)
        ) from exc

    ctx = ActionContext(
        tool_name=body.tool_name,
        tool_arguments=body.tool_arguments,
        agent_id=body.agent_id,
        session_id=body.session_id,
        deterministic_decision=body.deterministic_decision,
        reason=body.reason,
        matched_policy_id=body.matched_policy_id,
    )
    assessment = assess_action(provider, ctx)
    final = reconcile(
        body.deterministic_decision, assessment.decision, mode=org.ai_mode
    )
    return AssessOut(
        recommended_decision=assessment.decision,
        final_decision=final,
        mode=org.ai_mode,
        confidence=assessment.confidence,
        rationale=assessment.rationale,
        opinions=[
            AgentOpinionOut(
                role=o.role,
                decision=o.decision,
                confidence=o.confidence,
                rationale=o.rationale,
            )
            for o in assessment.opinions
        ],
        provider=config.provider,
        model=config.model,
        error=assessment.error,
    )


@router.post("/ai/rules/suggest", response_model=list[RuleSuggestionOut])
def suggest_rules(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> list[RuleSuggestion]:
    _require_ai(org)
    config = org_llm_config(org, settings)
    assert config is not None
    try:
        provider = get_provider(config)
    except LLMError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, detail=str(exc)
        ) from exc

    summary = build_pattern_summary(session, org.id)
    drafts = propose_rules(provider, pattern_summary=summary)
    created: list[RuleSuggestion] = []
    for draft in drafts:
        suggestion = RuleSuggestion(
            organization_id=org.id,
            title=draft.title,
            rationale=draft.rationale,
            severity=draft.severity,
            category=draft.category,
            spec=draft.spec,
            atlas_technique=draft.atlas_technique,
            owasp_llm=draft.owasp_llm,
            confidence=draft.confidence,
            source="ai",
            status=SuggestionStatus.PENDING.value,
        )
        session.add(suggestion)
        created.append(suggestion)
    session.flush()
    return created


@router.get("/ai/rules/suggestions", response_model=list[RuleSuggestionOut])
def list_suggestions(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    status_filter: Annotated[str | None, Query(alias="status")] = None,
) -> list[RuleSuggestion]:
    stmt = (
        select(RuleSuggestion)
        .where(RuleSuggestion.organization_id == org.id)
        .order_by(RuleSuggestion.created_at.desc())
        .limit(200)
    )
    if status_filter:
        stmt = stmt.where(RuleSuggestion.status == status_filter)
    return list(session.execute(stmt).scalars().all())


def _unique_rule_name(session: Session, org_id: str, base: str) -> str:
    name = base[:128] or "ai-rule"
    for suffix in range(0, 100):
        candidate = name if suffix == 0 else f"{name[:120]}-{suffix}"
        exists = session.execute(
            select(DetectionRule.id).where(
                DetectionRule.organization_id == org_id,
                DetectionRule.name == candidate,
            )
        ).first()
        if not exists:
            return candidate
    return f"{name[:110]}-{org_id[:8]}"


@router.post(
    "/ai/rules/suggestions/{suggestion_id}/accept",
    response_model=RuleSuggestionOut,
)
def accept_suggestion(
    suggestion_id: str,
    body: SuggestionReviewIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> RuleSuggestion:
    suggestion = get_owned(
        session, RuleSuggestion, suggestion_id, org, detail="suggestion not found"
    )
    if suggestion.status != SuggestionStatus.PENDING.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"suggestion already {suggestion.status}",
        )
    # Validate the AI-authored spec through the same schema as human rules.
    try:
        DetectionRuleSpec(**suggestion.spec)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"suggested spec is invalid: {exc}",
        ) from exc

    rule = DetectionRule(
        organization_id=org.id,
        name=_unique_rule_name(session, org.id, suggestion.title),
        description=f"AI-suggested: {suggestion.rationale}"[:2000],
        enabled=True,
        severity=suggestion.severity,
        category=suggestion.category,
        spec=suggestion.spec,
        atlas_technique=suggestion.atlas_technique,
        owasp_llm=suggestion.owasp_llm,
    )
    session.add(rule)
    try:
        with session.begin_nested():
            session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="rule name collision"
        ) from exc
    suggestion.status = SuggestionStatus.ACCEPTED.value
    suggestion.reviewed_by = body.reviewed_by
    suggestion.created_rule_id = rule.id
    session.flush()
    return suggestion


@router.post(
    "/ai/rules/suggestions/{suggestion_id}/reject",
    response_model=RuleSuggestionOut,
)
def reject_suggestion(
    suggestion_id: str,
    body: SuggestionReviewIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> RuleSuggestion:
    suggestion = get_owned(
        session, RuleSuggestion, suggestion_id, org, detail="suggestion not found"
    )
    if suggestion.status != SuggestionStatus.PENDING.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"suggestion already {suggestion.status}",
        )
    suggestion.status = SuggestionStatus.REJECTED.value
    suggestion.reviewed_by = body.reviewed_by
    session.flush()
    return suggestion
