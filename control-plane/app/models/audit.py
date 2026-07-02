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


class AuditEvent(IdMixin, TimestampMixin, Base):
    """One audit event as shipped by an SDK.

    The SDK-side AuditEvent (with Merkle chain fields) lands here; we
    keep the chain integrity columns alongside the indexed search
    columns so search is fast and verification is still possible.
    """

    __tablename__ = "audit_events"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )

    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_use_id: Mapped[str | None] = mapped_column(String(255))
    tool_arguments: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(1024), nullable=False)
    matched_policy_id: Mapped[str | None] = mapped_column(String(255))
    suggested_transform: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    context: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evaluator_version: Mapped[str] = mapped_column(String(64), nullable=False)

    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_audit_org_timestamp", "organization_id", "timestamp"),
        Index("ix_audit_org_agent", "organization_id", "agent_id"),
        Index("ix_audit_org_decision", "organization_id", "decision"),
        Index("ix_audit_org_tool", "organization_id", "tool_name"),
        Index("ix_audit_session", "session_id"),
        # At-least-once shipping retries: the SDK may ship the same event
        # twice (server received, ack lost). The hash is the natural
        # idempotency key; the ingest path swallows IntegrityError and
        # returns the existing row.
        UniqueConstraint("organization_id", "hash", name="uq_audit_org_hash"),
    )
