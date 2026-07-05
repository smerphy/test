"""Long-term telemetry aggregates.

When raw audit events age out of the hot store (see `app.services.retention`),
they are first rolled into per-(org, day, agent, decision) counts here. This
preserves queryable long-term trends and compliance decision-rate history
without keeping every raw row in the primary table — the core of bounding a
high-volume event store.
"""

from __future__ import annotations

from datetime import date

from sqlalchemy import Date, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class AuditDailyRollup(IdMixin, TimestampMixin, Base):
    __tablename__ = "audit_daily_rollups"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    day: Mapped[date] = mapped_column(Date, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "day",
            "agent_id",
            "decision",
            name="uq_audit_rollup_key",
        ),
        Index("ix_audit_rollup_org_day", "organization_id", "day"),
    )


__all__ = ["AuditDailyRollup"]
