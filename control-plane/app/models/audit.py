from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
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
from app.models.types import EncryptedJSON


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
    # Richest sensitive payload: sealed at rest when telemetry field
    # encryption is enabled (see app.models.types.EncryptedJSON).
    tool_arguments: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON, nullable=False
    )
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(1024), nullable=False)
    matched_policy_id: Mapped[str | None] = mapped_column(String(255))
    suggested_transform: Mapped[dict[str, Any] | None] = mapped_column(
        EncryptedJSON
    )
    context: Mapped[dict[str, Any]] = mapped_column(
        EncryptedJSON, nullable=False, default=dict
    )
    evaluator_version: Mapped[str] = mapped_column(String(64), nullable=False)

    # Data classification, derived server-side at ingest from a PII scan when
    # `EPHORATE_CLASSIFY_TELEMETRY` is on ("restricted" if the payload carried
    # PII, else "standard"). Drives classification-aware retention; not part of
    # the hashed event body.
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="standard", server_default="standard"
    )

    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Chain-linkage verification state. Under synchronous ingest this is True on
    # insert; under async-verify ingest (EPHORATE_AUDIT_ASYNC_VERIFY) events land
    # unverified and a background verifier flips them True in seq order (or
    # raises a tamper finding on a broken link).
    verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    # When this event was written to the authoritative cold archive (NULL =
    # not yet archived). The archive task selects NULL rows, writes them, then
    # stamps this — making the cold tier reliable rather than best-effort.
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_audit_org_timestamp", "organization_id", "timestamp"),
        Index("ix_audit_org_agent", "organization_id", "agent_id"),
        Index("ix_audit_org_decision", "organization_id", "decision"),
        Index("ix_audit_org_tool", "organization_id", "tool_name"),
        Index("ix_audit_org_class", "organization_id", "classification"),
        Index("ix_audit_org_verified", "organization_id", "verified"),
        Index("ix_audit_org_archived", "organization_id", "archived_at"),
        Index("ix_audit_session", "session_id"),
        # At-least-once shipping retries: the SDK may ship the same event
        # twice (server received, ack lost). The hash is the natural
        # idempotency key; the ingest path swallows IntegrityError and
        # returns the existing row.
        UniqueConstraint("organization_id", "hash", name="uq_audit_org_hash"),
    )
