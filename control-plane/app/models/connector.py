"""Outbound notification connectors — sync findings to on-call / ticketing.

Beyond the single OCSF finding webhook, an org can configure typed connectors
(PagerDuty, Opsgenie, Jira, ServiceNow, Slack, generic webhook). When a new
finding at/above a connector's minimum severity is raised, it is delivered in
that system's native payload. Connector credentials (routing keys, API tokens)
are encrypted at rest.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class ConnectorType(StrEnum):
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"
    JIRA = "jira"
    SERVICENOW = "servicenow"
    SLACK = "slack"
    WEBHOOK = "webhook"


class NotificationConnector(IdMixin, TimestampMixin, Base):
    __tablename__ = "notification_connectors"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    # Non-secret routing config (instance_url, project key, region, …).
    config: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    # Credential (routing key / API token / webhook URL) — encrypted at rest.
    secret: Mapped[str | None] = mapped_column(Text)
    min_severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="high", server_default="high"
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    last_status: Mapped[str | None] = mapped_column(String(16))
    last_error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_connector_org_name"
        ),
    )


__all__ = ["ConnectorType", "NotificationConnector"]
