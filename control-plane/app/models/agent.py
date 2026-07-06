"""Agent sensors — fleet management.

An `Agent` row is a registered SDK sensor: it reports in via heartbeat
(enrollment on first contact) so operators can see their fleet, each
sensor's version, and health (active vs stale by last-seen).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class Agent(IdMixin, TimestampMixin, Base):
    __tablename__ = "agents"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # The external agent identity used across audit/metric events.
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    agent_version: Mapped[str | None] = mapped_column(String(64))
    sdk_version: Mapped[str | None] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "agent_id", name="uq_agent_org_agentid"),
        Index("ix_agent_org_lastseen", "organization_id", "last_seen"),
    )


__all__ = ["Agent"]
