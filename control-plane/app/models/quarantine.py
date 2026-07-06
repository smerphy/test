"""Quarantine — the EDR response primitive.

A quarantine isolates an agent or a session: while active, the SDK denies
every tool call for the matching entity (a kill-switch), regardless of
policy. Quarantines are created manually by an analyst or automatically by
the response engine when a high-severity finding fires.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class QuarantineSource(StrEnum):
    MANUAL = "manual"
    AUTO = "auto"


class Quarantine(IdMixin, TimestampMixin, Base):
    __tablename__ = "quarantines"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # The isolated entity. At least one is set; agent_id isolates every
    # session of that agent, session_id isolates a single session.
    agent_id: Mapped[str | None] = mapped_column(String(255))
    session_id: Mapped[str | None] = mapped_column(String(255))

    reason: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[QuarantineSource] = mapped_column(
        String(16), nullable=False, default=QuarantineSource.MANUAL
    )
    # The finding that triggered an automatic quarantine, if any.
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL")
    )

    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(255))
    lifted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lifted_by: Mapped[str | None] = mapped_column(String(255))

    __table_args__ = (
        Index("ix_quarantine_org_active", "organization_id", "active"),
    )


__all__ = ["Quarantine", "QuarantineSource"]
