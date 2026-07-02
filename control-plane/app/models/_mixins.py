"""Shared column mixins."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column


def _new_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class IdMixin:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )


__all__ = ["IdMixin", "TimestampMixin"]
