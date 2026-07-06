"""Per-agent behavioral baseline (UEBA).

A snapshot of how an agent normally behaves over a training window — which
tools it calls and how often, its decision mix, and its breadth of tools and
sessions. Drift from this baseline (a never-before-seen tool, a spike in
denials) is what the detector turns into findings, giving the SIEM a behavioral
layer on top of the rule-based detections.

One current baseline per ``(organization, agent)`` — rebuilt on a schedule.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class AgentBaseline(IdMixin, TimestampMixin, Base):
    __tablename__ = "agent_baselines"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)

    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # {tool_name: count} and {decision: count} over the window.
    tool_counts: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    decision_counts: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    distinct_tools: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_sessions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "agent_id", name="uq_agent_baseline"
        ),
        Index("ix_agent_baseline_org", "organization_id"),
    )


__all__ = ["AgentBaseline"]
