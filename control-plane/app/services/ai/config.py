"""Resolve an org's opt-in AI configuration and build agent context.

BYOK: the LLM config is assembled from the org's own provider/model/key. The
service is unavailable unless the org has explicitly opted in AND supplied the
required fields — there is no platform-default vendor or key.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Finding, Organization
from app.models.finding import OPEN_FINDING_STATUSES
from app.services.ai.providers import SUPPORTED_PROVIDERS, LLMConfig
from app.services.crypto import unseal
from app.settings import Settings


def ai_available(org: Organization) -> bool:
    """True iff the org opted in and supplied a usable provider/model/key."""
    return bool(
        org.ai_enabled
        and org.ai_provider in SUPPORTED_PROVIDERS
        and org.ai_model
        and org.ai_api_key
    )


def org_llm_config(org: Organization, settings: Settings) -> LLMConfig | None:
    """Build the LLMConfig for an org, or None if AI is unavailable."""
    if not ai_available(org):
        return None
    return LLMConfig(
        provider=org.ai_provider,
        model=org.ai_model,
        api_key=unseal(org.ai_api_key) or "",
        base_url=org.ai_base_url,
        max_tokens=settings.ai_max_tokens,
        timeout_seconds=settings.ai_request_timeout_seconds,
        allow_private_endpoint=settings.ai_allow_private_endpoints,
    )


def build_pattern_summary(
    session: Session, org_id: str, *, lookback_hours: int = 168
) -> str:
    """Summarize recent findings + denials so the rule-author agent has signal."""
    since = datetime.now(UTC) - timedelta(hours=lookback_hours)
    since_naive = since.replace(tzinfo=None)

    findings = session.execute(
        select(Finding.title, Finding.severity, Finding.category, Finding.count)
        .where(
            Finding.organization_id == org_id,
            Finding.status.in_(OPEN_FINDING_STATUSES),
        )
        .order_by(Finding.count.desc())
        .limit(20)
    ).all()

    denials = session.execute(
        select(
            AuditEvent.matched_policy_id,
            AuditEvent.tool_name,
            func.count().label("n"),
        )
        .where(
            AuditEvent.organization_id == org_id,
            AuditEvent.decision == "deny",
            AuditEvent.timestamp >= since_naive,
        )
        .group_by(AuditEvent.matched_policy_id, AuditEvent.tool_name)
        .order_by(func.count().desc())
        .limit(20)
    ).all()

    lines = [f"Open findings (last {lookback_hours}h), by frequency:"]
    if findings:
        lines += [
            f"- {f.title} [{f.severity}/{f.category}] x{f.count}" for f in findings
        ]
    else:
        lines.append("- (none)")
    lines.append("")
    lines.append("Top denied tool calls (policy, tool, count):")
    if denials:
        lines += [
            f"- policy={d.matched_policy_id} tool={d.tool_name} x{d.n}"
            for d in denials
        ]
    else:
        lines.append("- (none)")
    return "\n".join(lines)


__all__ = ["ai_available", "build_pattern_summary", "org_llm_config"]
