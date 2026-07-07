"""SOAR response playbooks — automated finding-driven response.

A ``ResponsePlaybook`` is a *when → then*: a set of match conditions and an
ordered list of actions. When the detection engine raises a new finding, every
enabled playbook is evaluated in ``priority`` order; a playbook whose conditions
match runs its actions (quarantine the entity, notify connectors, forward to the
SIEM, tag/assign/triage the finding). ``stop_on_match`` short-circuits the rest.

Every run is recorded as a ``PlaybookExecution`` so the automated response is
auditable — which playbook fired on which finding, what it did, and whether each
action succeeded.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class PlaybookActionType(StrEnum):
    """The response actions a playbook step can take."""

    QUARANTINE = "quarantine"  # isolate the finding's agent/session (EDR)
    NOTIFY_CONNECTORS = "notify_connectors"  # dispatch to notification connectors
    FORWARD_SIEM = "forward_siem"  # POST to the org finding webhook
    TAG = "tag"  # add tags to finding.evidence["tags"]
    SET_STATUS = "set_status"  # move the finding's triage status
    ASSIGN = "assign"  # set the finding's assignee


class ResponsePlaybook(IdMixin, TimestampMixin, Base):
    __tablename__ = "response_playbooks"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    # Lower runs first. Ties broken by created_at.
    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=100, server_default="100"
    )
    # When this playbook matches, stop evaluating lower-priority playbooks.
    stop_on_match: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    # Match conditions (all present clauses must hold). Recognized keys:
    #   min_severity: str            finding.severity >= this
    #   categories: list[str]        finding.category in this set
    #   rule_ids: list[str]          finding.rule_id in this set
    #   sources: list[str]           finding.source in this set
    #   min_risk_score: float        risk_score(finding) >= this
    conditions: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    # Ordered actions: [{"type": "quarantine"}, {"type": "tag",
    # "params": {"tags": ["auto-triaged"]}}, ...].
    actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_playbook_org_name"
        ),
        Index("ix_playbook_org_enabled", "organization_id", "enabled"),
    )


class PlaybookExecution(IdMixin, TimestampMixin, Base):
    __tablename__ = "playbook_executions"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    playbook_id: Mapped[str] = mapped_column(
        ForeignKey("response_playbooks.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[str] = mapped_column(String(36), nullable=False)
    # Per-action outcomes: [{"type": "quarantine", "ok": true, "detail": "..."}].
    results: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )

    __table_args__ = (
        Index("ix_pbexec_org_finding", "organization_id", "finding_id"),
        Index("ix_pbexec_org_playbook", "organization_id", "playbook_id"),
    )


__all__ = ["PlaybookActionType", "PlaybookExecution", "ResponsePlaybook"]
