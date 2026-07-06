"""Custom detection rules (detection-as-code).

Lets an org author its own correlation rules as data (not code), evaluated
by the detection engine alongside the built-ins. The `spec` is a bounded,
structured match — no arbitrary code or regex — so a custom rule can never
be a ReDoS/RCE vector.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class DetectionRule(IdMixin, TimestampMixin, Base):
    __tablename__ = "detection_rules"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    # Structured match spec (validated by app.schemas.DetectionRuleSpec).
    spec: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    atlas_technique: Mapped[str | None] = mapped_column(String(64))
    owasp_llm: Mapped[str | None] = mapped_column(String(32))

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_detection_rule_org_name"
        ),
    )


__all__ = ["DetectionRule"]
