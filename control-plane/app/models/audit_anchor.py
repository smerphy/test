"""Immutable anchors over the tamper-evident audit chain.

Each audit chain (per agent+session) is append-only: an event's hash commits
the entire chain up to its seq. An *anchor* snapshots every chain's current
head — {agent, session, seq, hash} — computes a root over them, chains to the
previous anchor, and is published to external object storage. If the database
is later tampered with, the externally-held anchor still proves the prior
state: re-deriving a head and comparing to the anchor detects any alteration
of an event at or below the anchored seq. New events (higher seq) extend a
chain without invalidating past anchors.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class AuditAnchor(IdMixin, TimestampMixin, Base):
    __tablename__ = "audit_anchors"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # Number of chains + total events covered at anchor time.
    chain_count: Mapped[int] = mapped_column(Integer, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    # Root digest over the sorted chain heads.
    root: Mapped[str] = mapped_column(String(64), nullable=False)
    # Anchor-of-anchors chaining (tamper-evidence over the anchor series too).
    prev_anchor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    anchor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # The snapshot: [{agent, session, seq, hash}, ...].
    chains: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    # Where the anchor was externally published (object-store path), if any.
    published_to: Mapped[str | None] = mapped_column(String(1024))

    __table_args__ = (
        Index("ix_audit_anchor_org_created", "organization_id", "created_at"),
    )


__all__ = ["AuditAnchor"]
