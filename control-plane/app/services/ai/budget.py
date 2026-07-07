"""BYOK cost budgeting: meter AI token usage, enforce a monthly budget, alert.

Wraps a provider so every ``complete()`` call accrues estimated token usage
and cost into the org's monthly :class:`AIUsage` ledger. Before running an AI
operation, callers check :func:`is_over_budget`; explicit endpoints 402 when
over, and passive triage degrades to non-AI scoring. Crossing the budget emits
a one-time structured alert (and a best-effort webhook if configured).
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AIUsage, Organization
from app.services.ai.providers import LLMProvider
from app.settings import Settings

_log = structlog.get_logger(__name__)


def current_month(now: datetime | None = None) -> str:
    return (now or datetime.now(UTC)).strftime("%Y-%m")


def _estimate_tokens(text: str) -> int:
    # ~4 chars/token is a good cross-tokenizer approximation for budgeting.
    return max(1, len(text) // 4)


def _cost(input_tokens: int, output_tokens: int, settings: Settings) -> float:
    return (
        input_tokens / 1_000_000 * settings.ai_price_input_per_mtok
        + output_tokens / 1_000_000 * settings.ai_price_output_per_mtok
    )


def month_to_date(session: Session, org_id: str) -> AIUsage | None:
    return session.execute(
        select(AIUsage).where(
            AIUsage.organization_id == org_id,
            AIUsage.month == current_month(),
        )
    ).scalar_one_or_none()


def is_over_budget(session: Session, org: Organization, settings: Settings) -> bool:
    if org.ai_monthly_budget_usd is None:
        return False
    usage = month_to_date(session, org.id)
    spent = usage.cost_usd if usage is not None else 0.0
    return spent >= org.ai_monthly_budget_usd


def record_usage(
    session: Session,
    org: Organization,
    settings: Settings,
    *,
    input_tokens: int,
    output_tokens: int,
) -> None:
    """Accrue usage into the current month's ledger; alert on first crossing."""
    month = current_month()
    usage = session.execute(
        select(AIUsage).where(
            AIUsage.organization_id == org.id, AIUsage.month == month
        )
    ).scalar_one_or_none()
    if usage is None:
        usage = AIUsage(
            organization_id=org.id,
            month=month,
            input_tokens=0,
            output_tokens=0,
            cost_usd=0.0,
            call_count=0,
            alerted=False,
        )
        session.add(usage)
    usage.input_tokens += input_tokens
    usage.output_tokens += output_tokens
    usage.cost_usd += _cost(input_tokens, output_tokens, settings)
    usage.call_count += 1

    budget = org.ai_monthly_budget_usd
    if budget is not None and usage.cost_usd >= budget and not usage.alerted:
        usage.alerted = True
        _log.warning(
            "ai_budget_exceeded",
            org=org.slug,
            month=month,
            spent_usd=round(usage.cost_usd, 4),
            budget_usd=budget,
        )
        _notify_budget(org, usage, budget)
    session.flush()


def _notify_budget(org: Organization, usage: AIUsage, budget: float) -> None:
    """Best-effort webhook alert on budget crossing (egress-guarded)."""
    if not org.finding_webhook_url:
        return
    import httpx

    from app.services.egress import is_safe_webhook_url

    if not is_safe_webhook_url(org.finding_webhook_url):
        return
    payload = {
        "type": "ephorate.ai.budget_exceeded",
        "org": org.slug,
        "month": usage.month,
        "spent_usd": round(usage.cost_usd, 4),
        "budget_usd": budget,
    }
    # Alerting must never break the request.
    with contextlib.suppress(Exception):
        httpx.Client(timeout=10.0).post(org.finding_webhook_url, json=payload)


class MeteredProvider(LLMProvider):
    """Provider wrapper that records estimated usage per completion.

    Subclasses LLMProvider for typing but wraps an already-constructed inner
    provider, so it deliberately skips the base __init__ (endpoint/egress
    setup already happened on the inner provider)."""

    def __init__(
        self,
        inner: LLMProvider,
        session: Session,
        org: Organization,
        settings: Settings,
    ) -> None:
        self._inner = inner
        self._session = session
        self._org = org
        self._settings = settings

    def complete(self, *, system: str, user: str) -> str:
        out = self._inner.complete(system=system, user=user)
        record_usage(
            self._session,
            self._org,
            self._settings,
            input_tokens=_estimate_tokens(system) + _estimate_tokens(user),
            output_tokens=_estimate_tokens(out),
        )
        return out


def metered(
    inner: LLMProvider, session: Session, org: Organization, settings: Settings
) -> MeteredProvider:
    return MeteredProvider(inner, session, org, settings)


__all__ = [
    "MeteredProvider",
    "current_month",
    "is_over_budget",
    "metered",
    "month_to_date",
    "record_usage",
]
