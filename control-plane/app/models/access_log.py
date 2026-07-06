"""Access log — an audit trail of who viewed or exported sensitive data.

Distinct from `AuditEvent` (which logs agent *tool-call decisions*), this logs
*human/credential access* to the platform's sensitive read/export surfaces:
audit search, findings, metrics, reports, investigations. It is the evidence a
SOC2 / ISO auditor asks for — "show me who looked at what, and when."
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class AccessLog(IdMixin, TimestampMixin, Base):
    __tablename__ = "access_logs"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # Who: an email (session user) or the credential kind (api_key).
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # What: a logical resource ("audit", "findings", …) + action (read|export).
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_access_log_org_created", "organization_id", "created_at"),
    )


__all__ = ["AccessLog"]
