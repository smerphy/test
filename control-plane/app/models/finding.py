"""Security findings — the SIEM/EDR detection primitive.

A `Finding` is raised by a detection rule that correlates one or more
audit/metric events into a security-relevant signal (a prompt-injection
attempt, a repeated-denial burst, an injection→exfil kill-chain, an
anomalous new tool, ...). Findings are the analyst-facing unit: they carry
severity, a MITRE ATLAS / OWASP LLM mapping, evidence, and a triage
lifecycle (open → triaging → resolved / false_positive).

Findings dedupe on `(organization_id, dedup_key)` while OPEN/TRIAGING, so a
detection that keeps firing for the same entity updates `last_seen`/`count`
instead of spamming; once resolved, a fresh trigger opens a new finding.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFIL = "data_exfil"
    ABUSE = "abuse"
    POLICY_VIOLATION = "policy_violation"
    APPROVAL_ABUSE = "approval_abuse"
    ANOMALY = "anomaly"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGING = "triaging"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# Statuses in which a finding is still "live" and should be updated in place
# by a re-firing detection rather than duplicated.
OPEN_FINDING_STATUSES = (FindingStatus.OPEN, FindingStatus.TRIAGING)


class Finding(IdMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # The detection rule that raised this finding (e.g. "repeated-denials").
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        String(16), nullable=False
    )
    category: Mapped[FindingCategory] = mapped_column(
        String(32), nullable=False
    )
    status: Mapped[FindingStatus] = mapped_column(
        String(16), nullable=False, default=FindingStatus.OPEN
    )

    # The entity the finding is about (either may be null for org-wide signals).
    agent_id: Mapped[str | None] = mapped_column(String(255))
    session_id: Mapped[str | None] = mapped_column(String(255))

    # Stable key for dedup/upsert across detection runs.
    dedup_key: Mapped[str] = mapped_column(String(512), nullable=False)
    # Number of correlated events / times the rule matched.
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # Correlated evidence (audit event ids, a summary, matched policies, ...).
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    # Threat-framework mapping.
    atlas_technique: Mapped[str | None] = mapped_column(String(64))
    owasp_llm: Mapped[str | None] = mapped_column(String(32))

    # Triage.
    assignee: Mapped[str | None] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[str | None] = mapped_column(String(255))

    __table_args__ = (
        Index("ix_finding_org_status", "organization_id", "status"),
        Index("ix_finding_org_severity", "organization_id", "severity"),
        Index("ix_finding_org_dedup", "organization_id", "dedup_key"),
    )


__all__ = [
    "OPEN_FINDING_STATUSES",
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "FindingStatus",
]
