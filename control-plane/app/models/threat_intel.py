"""Threat-intelligence feeds and indicators (IOCs).

A `ThreatFeed` is a configured source of indicators — a remote URL polled on a
schedule (STIX/TAXII, MISP, CSV, JSON, or a plaintext list) or a manual,
analyst-curated feed. Each feed yields `ThreatIndicator` rows: normalized IOCs
(malicious domains/IPs/URLs, file hashes, malicious tool/package names, and
LLM-specific signatures like known prompt-injection payloads or regexes).

Indicators are consumed by the detection engine: audit events whose tool name
or arguments match an active indicator raise a threat-intel finding (mapped to
MITRE ATLAS / OWASP LLM), so external intelligence directly drives detection
and — for CRITICAL matches — automated response.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._mixins import IdMixin, TimestampMixin


class IndicatorType(StrEnum):
    """Kinds of indicator Ephorate can match against agent activity."""

    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    SHA256 = "sha256"
    MD5 = "md5"
    EMAIL = "email"
    # Malicious tool/function an agent might be induced to call.
    TOOL_NAME = "tool_name"
    # Malicious dependency (supply-chain), e.g. a typosquatted package.
    PACKAGE = "package"
    # A literal string that flags a known prompt-injection / jailbreak payload
    # (substring match, case-insensitive).
    PROMPT_SIGNATURE = "prompt_signature"
    # A regular expression evaluated over serialized tool arguments.
    REGEX = "regex"


# Indicator types matched by exact (normalized) equality vs. free-text scan.
EXACT_MATCH_TYPES = frozenset(
    {
        IndicatorType.DOMAIN,
        IndicatorType.IP,
        IndicatorType.URL,
        IndicatorType.SHA256,
        IndicatorType.MD5,
        IndicatorType.EMAIL,
        IndicatorType.PACKAGE,
    }
)


class FeedFormat(StrEnum):
    JSON = "json"
    CSV = "csv"
    PLAINTEXT = "plaintext"
    STIX = "stix"
    MISP = "misp"
    # TAXII 2.1 collection: `url` is the collection objects endpoint; the
    # server returns STIX 2.x objects, polled incrementally with `added_after`.
    TAXII = "taxii"


class TLP(StrEnum):
    """Traffic Light Protocol sharing marking."""

    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class FeedSyncStatus(StrEnum):
    NEVER = "never"
    OK = "ok"
    ERROR = "error"


class ThreatFeed(IdMixin, TimestampMixin, Base):
    __tablename__ = "threat_feeds"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Null URL = a manual feed whose indicators are curated via the API.
    url: Mapped[str | None] = mapped_column(String(2048))
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    # For single-type feeds (plaintext / JSON-string lists) the type every
    # value is assigned. Null for self-describing formats (STIX/MISP/CSV/JSON
    # objects).
    default_indicator_type: Mapped[str | None] = mapped_column(String(32))
    # Optional single request header sent when fetching (e.g. an auth token):
    # "Authorization: Token abc". Stored as-is; treat as a secret.
    auth_header: Mapped[str | None] = mapped_column(String(1024))
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    tlp: Mapped[str] = mapped_column(
        String(8), nullable=False, default=TLP.AMBER.value, server_default="amber"
    )
    # Default confidence/severity applied to indicators that don't carry
    # their own.
    default_confidence: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50, server_default="50"
    )
    default_severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="high", server_default="high"
    )
    refresh_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60, server_default="60"
    )
    last_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=FeedSyncStatus.NEVER.value,
        server_default="never",
    )
    last_error: Mapped[str | None] = mapped_column(Text)
    indicator_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", name="uq_threat_feed_org_name"
        ),
    )


class ThreatIndicator(IdMixin, TimestampMixin, Base):
    __tablename__ = "threat_indicators"

    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # Null feed = manually added indicator.
    feed_id: Mapped[str | None] = mapped_column(
        ForeignKey("threat_feeds.id", ondelete="SET NULL")
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    # Normalized indicator value (lowercased where appropriate).
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    confidence: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50, server_default="50"
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="high", server_default="high"
    )
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    references: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    description: Mapped[str | None] = mapped_column(Text)
    tlp: Mapped[str] = mapped_column(
        String(8), nullable=False, default=TLP.AMBER.value, server_default="amber"
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # Optional intel expiry; expired indicators are ignored by matching.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "type", "value", name="uq_indicator_org_type_value"
        ),
        Index("ix_indicator_org_type", "organization_id", "type"),
        Index("ix_indicator_org_enabled", "organization_id", "enabled"),
        Index("ix_indicator_feed", "feed_id"),
    )


__all__ = [
    "EXACT_MATCH_TYPES",
    "TLP",
    "FeedFormat",
    "FeedSyncStatus",
    "IndicatorType",
    "ThreatFeed",
    "ThreatIndicator",
]
