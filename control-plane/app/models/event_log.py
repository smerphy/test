"""Durable partitioned event log (the ingest front) + consumer offsets.

``LogRecord`` is an append-only, ordered log: its integer ``id`` is the
monotonic offset. Records carry a ``partition_key`` (org:agent:session for
audit, org for metrics) so a partition's events keep arrival order — consumers
that read by ascending ``id`` see each key's records in order, which is exactly
what the per-chain hash linkage needs.

``LogOffset`` tracks, per (topic, consumer_group), the last offset a consumer
has committed. Multiple consumer groups read the same log independently — the
Postgres hot-store materializer and the columnar/analytics sink are two such
groups — so the log fans out to every downstream store and each can lag or be
replayed on its own.

This SQL-backed log is the durable default (works on Postgres/SQLite with no
extra infrastructure). Production can swap in Kafka/Redpanda behind the same
``EventLog`` interface; the table then becomes just the dev/test backend.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import _now


class LogRecord(Base):
    """One appended record. ``id`` is the monotonic per-log offset."""

    __tablename__ = "log_records"

    # Autoincrement PK = the offset. Not the uuid IdMixin: consumers need a
    # monotonic cursor to page through the log. BigInteger on Postgres, but
    # INTEGER on SQLite so it aliases rowid and autoincrements in tests.
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    topic: Mapped[str] = mapped_column(String(64), nullable=False)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # Ordering key: same key -> same logical partition -> arrival order kept.
    partition_key: Mapped[str] = mapped_column(String(512), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    __table_args__ = (
        # The consumer poll: WHERE topic = ? AND id > ? ORDER BY id.
        Index("ix_log_topic_id", "topic", "id"),
    )


class LogOffset(Base):
    """Committed read position for one (topic, consumer_group)."""

    __tablename__ = "log_offsets"

    topic: Mapped[str] = mapped_column(String(64), primary_key=True)
    consumer_group: Mapped[str] = mapped_column(String(128), primary_key=True)
    last_offset: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )


__all__ = ["LogOffset", "LogRecord"]
