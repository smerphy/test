"""AI-proposed detection rules awaiting human review.

The rule-improvement agents analyze recent findings and denial patterns and
draft candidate detection rules. Suggestions are never auto-applied: an admin
reviews and accepts (which materializes a `DetectionRule`) or rejects. This is
the "improve the ruleset over time" loop, kept human-in-the-loop.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class SuggestionStatus(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class RuleSuggestion(IdMixin, TimestampMixin, Base):
    __tablename__ = "rule_suggestions"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    # Structured DetectionRuleSpec (validated on accept).
    spec: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    atlas_technique: Mapped[str | None] = mapped_column(String(64))
    owasp_llm: Mapped[str | None] = mapped_column(String(32))
    # Confidence from the agent panel (0-1) and the models that produced it.
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    source: Mapped[str] = mapped_column(
        String(64), nullable=False, default="ai", server_default="ai"
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=SuggestionStatus.PENDING.value,
        server_default="pending",
    )
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    # If accepted, the DetectionRule it created.
    created_rule_id: Mapped[str | None] = mapped_column(String(36))

    __table_args__ = (
        Index(
            "ix_rule_suggestion_org_status", "organization_id", "status"
        ),
    )


__all__ = ["RuleSuggestion", "SuggestionStatus"]
