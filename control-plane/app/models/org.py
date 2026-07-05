from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class Organization(IdMixin, TimestampMixin, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Slack-compatible incoming-webhook URL that pending approvals are posted
    # to. Null = notifications disabled (the dashboard inbox is still the
    # source of truth).
    approval_webhook_url: Mapped[str | None] = mapped_column(String(1024))
    # When true, a CRITICAL finding automatically quarantines its entity
    # (EDR auto-response). Off by default — opt in per org.
    auto_quarantine: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )

    users: Mapped[list[User]] = relationship(back_populates="organization")
    projects: Mapped[list[Project]] = relationship(back_populates="organization")  # type: ignore[name-defined]  # noqa: F821


class User(IdMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str | None] = mapped_column(String(255))
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    organization: Mapped[Organization] = relationship(back_populates="users")
