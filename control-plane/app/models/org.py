from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class Role(StrEnum):
    """RBAC role, ascending in privilege.

    - ``viewer``  — read-only access to every resource.
    - ``analyst`` — SOC operations: triage findings, resolve approvals,
      create/lift quarantines, acknowledge/evaluate alerts, ingest telemetry.
    - ``admin``   — configuration: policies, alert rules, detection rules,
      org settings.
    - ``owner``   — everything, plus user/role management.

    The numeric ordering lives in ``app.rbac.ROLE_LEVELS``; a higher role
    always subsumes the privileges of the ones below it.
    """

    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"
    OWNER = "owner"


class Organization(IdMixin, TimestampMixin, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Slack-compatible incoming-webhook URL that pending approvals are posted
    # to. Null = notifications disabled (the dashboard inbox is still the
    # source of truth).
    approval_webhook_url: Mapped[str | None] = mapped_column(String(1024))
    # When true, a CRITICAL finding automatically quarantines its entity
    # (EDR auto-response). Off by default — opt in per org.
    auto_quarantine: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    # Forward new findings at/above `finding_min_severity` to this webhook
    # (Slack / generic / SIEM HEC-style). Null = forwarding disabled.
    finding_webhook_url: Mapped[str | None] = mapped_column(String(1024))
    finding_min_severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="high", server_default="high"
    )
    # Findings scored below this AI fidelity (0-1) are hidden from the default
    # dashboard view (kept, not dropped) to keep speculative signal out of the
    # way. 0 = show everything.
    finding_fidelity_threshold: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.4, server_default="0.4"
    )
    # When true, PII in agent-reported observations is masked on ingest
    # (before storage and before the AI triage panel sees it). Off by default.
    pii_redaction_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    # Global kill-switch (EDR): when engaged, every agent/session is treated as
    # quarantined (denied inline via /quarantines/check) except those with an
    # active break-glass grant. Owner-controlled emergency stop.
    halt_all: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )

    # --- AI-native advisory (opt-in, bring-your-own-key, vendor-neutral) ---
    # Off by default: the deterministic policy engine is fully functional
    # without any AI. When enabled, a multi-agent panel advises on ambiguous
    # decisions and proposes rule improvements.
    ai_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    # advisory = recommendations only (engine decision unchanged);
    # enforce = the AI may make a decision *more* restrictive (never looser).
    ai_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="advisory", server_default="advisory"
    )
    # Vendor-neutral provider selector + model. "anthropic" (Messages API) or
    # "openai_compat" (OpenAI Chat Completions — covers OpenAI, Azure, Groq,
    # Together, Mistral, Ollama, vLLM, LM Studio, …).
    ai_provider: Mapped[str] = mapped_column(
        String(32), nullable=False, default="", server_default=""
    )
    ai_model: Mapped[str] = mapped_column(
        String(128), nullable=False, default="", server_default=""
    )
    # Optional base-URL override (self-hosted gateway / non-default vendor).
    ai_base_url: Mapped[str | None] = mapped_column(String(1024))
    # BYO API key. Secret: encrypted at rest, never serialized back out.
    ai_api_key: Mapped[str | None] = mapped_column(String(1024))
    # Monthly BYOK spend cap (USD). Null = no budget. Over budget, explicit AI
    # endpoints 402 and passive triage degrades to non-AI scoring.
    ai_monthly_budget_usd: Mapped[float | None] = mapped_column(Float)

    # --- FinOps: agent LLM spend budget ----------------------------------
    # Monthly budget (USD) for the org's *agent* Claude/LLM spend as tracked by
    # MetricEvent.cost_usd. Distinct from ai_monthly_budget_usd (which caps
    # Ephorate's own advisory service). Powers the financial-tracking section's
    # burn-down + end-of-month forecast. Null = no budget (tracking only).
    monthly_cost_budget_usd: Mapped[float | None] = mapped_column(Float)
    # Hard enforcement: when true and month-to-date agent spend >=
    # monthly_cost_budget_usd, agents are denied inline (via /quarantines/check).
    enforce_cost_budget: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    # Per-agent monthly spend cap (USD). An agent over its quota is denied even
    # if the org is under its overall budget. Null = no per-agent quota.
    agent_cost_quota_usd: Mapped[float | None] = mapped_column(Float)

    users: Mapped[list[User]] = relationship(back_populates="organization")
    projects: Mapped[list[Project]] = relationship(back_populates="organization")  # type: ignore[name-defined]  # noqa: F821


class User(IdMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str | None] = mapped_column(String(255))
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # RBAC role within the organization. Stored as the StrEnum value so it
    # compares as a plain string. Defaults to ``admin`` to preserve access
    # for pre-RBAC rows/deployments; the first user of a fresh org is
    # promoted to ``owner`` at creation time.
    role: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Role.ADMIN.value, server_default="admin"
    )
    # Provisioning + session management. `active=False` (SCIM deprovision)
    # denies the user; `session_epoch` is stamped into the session cookie and
    # bumped to revoke all existing sessions. `external_id` is the IdP's SCIM id.
    active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    external_id: Mapped[str | None] = mapped_column(String(255))
    session_epoch: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # TOTP multi-factor auth. `mfa_secret` is a base32 seed, encrypted at rest.
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    mfa_secret: Mapped[str | None] = mapped_column(String(255))

    organization: Mapped[Organization] = relationship(back_populates="users")
