"""Per-org monthly AI usage ledger (BYOK cost budgeting).

Accumulates estimated token usage and cost for each organization per calendar
month so the platform can enforce a monthly budget on BYO-key AI calls and
alert when a tenant approaches / crosses it. Cost is an estimate (token counts
are derived from payload size; price from configurable per-Mtok rates), which
is sufficient as a spend guardrail.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class AIUsage(IdMixin, TimestampMixin, Base):
    __tablename__ = "ai_usage"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # Calendar month, "YYYY-MM".
    month: Mapped[str] = mapped_column(String(7), nullable=False)
    input_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    output_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    cost_usd: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0, server_default="0"
    )
    call_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # Set once we've alerted on crossing the budget this month (idempotent).
    alerted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "month", name="uq_ai_usage_org_month"),
    )


__all__ = ["AIUsage"]
