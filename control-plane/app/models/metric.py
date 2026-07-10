from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class MetricEvent(IdMixin, TimestampMixin, Base):
    """One Claude API call worth of telemetry.

    Shipped by SDKs (Python `AnthropicMonitor`, TS equivalent). Distinct
    from `AuditEvent`: audit logs *decisions*, metrics log *every Claude
    request* with token counts, latency, cost, and outcome.
    """

    __tablename__ = "metric_events"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(255))

    # Claude / Anthropic specifics.
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    operation: Mapped[str] = mapped_column(
        String(64), nullable=False, default="messages.create"
    )
    request_id: Mapped[str | None] = mapped_column(String(128), index=True)

    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Outcome.
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # success|error|rate_limited
    stop_reason: Mapped[str | None] = mapped_column(String(32))
    error_type: Mapped[str | None] = mapped_column(String(128))

    # Optional extras.
    tools_used: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON, nullable=False, default=dict
    )

    __table_args__ = (
        Index("ix_metric_org_timestamp", "organization_id", "timestamp"),
        Index("ix_metric_org_model", "organization_id", "model"),
        Index("ix_metric_org_agent", "organization_id", "agent_id"),
        Index("ix_metric_org_status", "organization_id", "status"),
        Index("ix_metric_org_project", "organization_id", "project_id"),
        # Idempotency key for at-least-once shipping: a retried metric carrying
        # the same request_id must not create a duplicate row (which would
        # double-count cost/tokens and wrongly trip spend enforcement). NULL
        # request_ids are distinct under a unique constraint on both SQLite and
        # Postgres, so metrics without a request_id are unaffected.
        UniqueConstraint(
            "organization_id", "request_id", name="uq_metric_org_request"
        ),
    )
