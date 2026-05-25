"""Pydantic request / response schemas. Decoupled from ORM models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from app.models import ApprovalStatus, ReportStatus, RolloutState


def _canonical_timestamp(value: datetime) -> str:
    """Match the SDK's wire format: `YYYY-MM-DDTHH:MM:SS.sssZ`."""
    aware = value if value.tzinfo else value.replace(tzinfo=UTC)
    aware = aware.astimezone(UTC)
    ms = aware.microsecond // 1000
    return f"{aware.strftime('%Y-%m-%dT%H:%M:%S')}.{ms:03d}Z"

_BASE = ConfigDict(from_attributes=True, extra="forbid")


class OrganizationOut(BaseModel):
    model_config = _BASE
    id: str
    name: str
    slug: str


class ProjectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")


class ProjectOut(BaseModel):
    model_config = _BASE
    id: str
    organization_id: str
    name: str
    slug: str


class PolicyBundleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None


class PolicyBundleOut(BaseModel):
    model_config = _BASE
    id: str
    project_id: str
    name: str
    description: str | None
    version_count: int = 0


class PolicyVersionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    yaml_text: str = Field(..., min_length=1)
    notes: str | None = None
    author_email: str | None = None


class PolicyVersionOut(BaseModel):
    model_config = _BASE
    id: str
    bundle_id: str
    version_number: int
    yaml_text: str
    policy_count: int
    author_email: str | None
    notes: str | None
    created_at: datetime


class PolicyVersionSummary(BaseModel):
    """Lightweight version row for list endpoints (no yaml_text)."""

    model_config = _BASE
    id: str
    bundle_id: str
    version_number: int
    policy_count: int
    author_email: str | None
    notes: str | None
    created_at: datetime


class PolicyRolloutIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version_id: str
    state: RolloutState
    rollout_percentage: int = Field(default=100, ge=0, le=100)


class PolicyRolloutOut(BaseModel):
    model_config = _BASE
    id: str
    version_id: str
    state: RolloutState
    rollout_percentage: int


class AuditEventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seq: int = Field(..., ge=0)
    timestamp: datetime
    agent_id: str
    session_id: str
    tool_name: str
    tool_use_id: str | None = None
    tool_arguments: dict[str, Any]
    decision: str
    reason: str
    matched_policy_id: str | None = None
    suggested_transform: dict[str, Any] | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    evaluator_version: str
    prev_hash: str = Field(..., min_length=64, max_length=64)
    hash: str = Field(..., min_length=64, max_length=64)

    @field_serializer("timestamp")
    def _serialize_timestamp(self, value: datetime) -> str:
        return _canonical_timestamp(value)


class AuditEventOut(BaseModel):
    model_config = _BASE
    id: str
    organization_id: str
    seq: int
    timestamp: datetime
    agent_id: str
    session_id: str
    tool_name: str
    tool_use_id: str | None
    tool_arguments: dict[str, Any]
    decision: str
    reason: str
    matched_policy_id: str | None
    suggested_transform: dict[str, Any] | None
    context: dict[str, Any]
    evaluator_version: str
    prev_hash: str
    hash: str


class AuditIngestResult(BaseModel):
    accepted: int
    rejected: int
    errors: list[str] = Field(default_factory=list)


class ApprovalResolveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approved: bool
    resolved_by: str | None = None


class ApprovalRequestOut(BaseModel):
    model_config = _BASE
    id: str
    agent_id: str
    session_id: str
    tool_name: str
    tool_arguments: dict[str, Any]
    policy_id: str | None
    reason: str
    status: ApprovalStatus
    resolved_at: datetime | None
    resolved_by: str | None
    created_at: datetime


class ComplianceReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework: str = Field(..., pattern=r"^(nist_ai_rmf|iso_42001|eu_ai_act)$")
    period_start: datetime
    period_end: datetime


class ComplianceReportOut(BaseModel):
    model_config = _BASE
    id: str
    framework: str
    period_start: datetime
    period_end: datetime
    status: ReportStatus
    summary: dict[str, Any] | None
    error: str | None
    created_at: datetime
