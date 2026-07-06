"""Break-glass grants: time-boxed exceptions to the global kill-switch.

When the org kill-switch (``Organization.halt_all``) is engaged every agent is
halted — except an agent with an active (non-expired) break-glass grant, so a
trusted remediation agent can keep operating while everything else is frozen.
Every grant is attributed and time-boxed and lives on the record for the audit
trail.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class BreakGlassGrant(IdMixin, TimestampMixin, Base):
    __tablename__ = "break_glass_grants"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # The agent exempted from the kill-switch for the window.
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    granted_by: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_break_glass_org_agent", "organization_id", "agent_id"),
    )


__all__ = ["BreakGlassGrant"]
