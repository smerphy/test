from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class AlertMetric(StrEnum):
    COST_USD = "cost_usd"
    INPUT_TOKENS = "input_tokens"
    OUTPUT_TOKENS = "output_tokens"
    TOTAL_TOKENS = "total_tokens"
    DURATION_MS = "duration_ms"
    REQUEST_COUNT = "request_count"
    ERROR_COUNT = "error_count"
    ERROR_RATE = "error_rate"
    DENY_COUNT = "deny_count"


class AlertAggregation(StrEnum):
    SUM = "sum"
    AVG = "avg"
    P50 = "p50"
    P95 = "p95"
    P99 = "p99"
    MAX = "max"
    COUNT = "count"
    RATE = "rate"


class AlertComparison(StrEnum):
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertChannel(StrEnum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    EMAIL = "email"


class AlertState(StrEnum):
    FIRING = "firing"
    RESOLVED = "resolved"


class AlertRule(IdMixin, TimestampMixin, Base):
    """Threshold-based alert rule evaluated against a rolling window
    of `MetricEvent` rows.

    Example: "fire if total_tokens summed over the last 15 minutes
    exceeds 1,000,000, grouped by model, severity=warning, route to
    Slack."
    """

    __tablename__ = "alert_rules"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    metric: Mapped[AlertMetric] = mapped_column(
        Enum(AlertMetric, native_enum=False, length=32), nullable=False
    )
    aggregation: Mapped[AlertAggregation] = mapped_column(
        Enum(AlertAggregation, native_enum=False, length=16), nullable=False
    )
    window_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    comparison: Mapped[AlertComparison] = mapped_column(
        Enum(AlertComparison, native_enum=False, length=8),
        nullable=False,
        default=AlertComparison.GT,
    )

    # Optional grouping (per-model, per-agent, per-project).
    group_by: Mapped[str | None] = mapped_column(String(32))
    # Optional pre-filter (e.g. only requests where model = claude-opus-4-7).
    filter_model: Mapped[str | None] = mapped_column(String(128))
    filter_agent_id: Mapped[str | None] = mapped_column(String(255))

    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, native_enum=False, length=16),
        nullable=False,
        default=AlertSeverity.WARNING,
    )

    # Routing.
    channel: Mapped[AlertChannel] = mapped_column(
        Enum(AlertChannel, native_enum=False, length=16), nullable=False
    )
    target: Mapped[str] = mapped_column(String(1024), nullable=False)
    cooldown_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=15)

    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AlertEvent(IdMixin, TimestampMixin, Base):
    """One firing of an alert rule. Keeps a history for the inbox UI."""

    __tablename__ = "alert_events"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(
        ForeignKey("alert_rules.id", ondelete="CASCADE"), nullable=False
    )

    fired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[AlertState] = mapped_column(
        Enum(AlertState, native_enum=False, length=16),
        nullable=False,
        default=AlertState.FIRING,
    )

    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    group_key: Mapped[str | None] = mapped_column(String(255))

    delivered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    delivery_error: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_alert_org_fired", "organization_id", "fired_at"),
        Index("ix_alert_org_state", "organization_id", "state"),
        Index("ix_alert_rule", "rule_id"),
    )
