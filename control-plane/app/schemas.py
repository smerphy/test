"""Pydantic request / response schemas. Decoupled from ORM models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from praetor_engine.audit_hash import canonical_timestamp as _canonical_timestamp
from praetor_engine.types import Decision
from pydantic import BaseModel, ConfigDict, Field, field_serializer

from app.models import (
    AlertAggregation,
    AlertChannel,
    AlertComparison,
    AlertMetric,
    AlertSeverity,
    AlertState,
    ApprovalStatus,
    ReportStatus,
    RolloutState,
)

_BASE = ConfigDict(from_attributes=True, extra="forbid")


class OrganizationOut(BaseModel):
    model_config = _BASE
    id: str
    name: str
    slug: str
    approval_webhook_url: str | None = None


class OrganizationUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Slack-compatible incoming-webhook URL for pending-approval
    # notifications. Pass null to disable.
    approval_webhook_url: str | None = Field(default=None, max_length=1024)


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
    decision: Decision
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

    @field_serializer("decision")
    def _serialize_decision(self, value: Decision) -> str:
        # Hash body must contain the raw wire string ("allow"), not "Decision.ALLOW".
        return value.value


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


class ApprovalCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1, max_length=255)
    session_id: str = Field(..., min_length=1, max_length=255)
    tool_name: str = Field(..., min_length=1, max_length=255)
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    policy_id: str | None = None
    reason: str


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
    expires_at: datetime | None
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


# ----------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------


class MetricEventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: datetime
    agent_id: str
    session_id: str | None = None
    model: str
    operation: str = "messages.create"
    request_id: str | None = None
    duration_ms: int = Field(..., ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_read_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)
    cost_usd: float | None = None  # SDK can ship pre-computed cost
    status: str
    stop_reason: str | None = None
    error_type: str | None = None
    tools_used: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MetricEventOut(BaseModel):
    model_config = _BASE
    id: str
    organization_id: str
    timestamp: datetime
    agent_id: str
    session_id: str | None
    model: str
    operation: str
    request_id: str | None
    duration_ms: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: float
    status: str
    stop_reason: str | None
    error_type: str | None
    tools_used: list[str]


class MetricBucket(BaseModel):
    bucket_start: datetime
    request_count: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cost_usd: float
    error_count: int
    avg_duration_ms: float


class MetricAggregateResponse(BaseModel):
    bucket_size_minutes: int
    group_by: str | None
    buckets: list[MetricBucket]
    by_group: dict[str, list[MetricBucket]] = Field(default_factory=dict)


class MetricIngestResult(BaseModel):
    accepted: int
    rejected: int
    errors: list[str] = Field(default_factory=list)


# ----------------------------------------------------------------
# Alert rules
# ----------------------------------------------------------------


class AlertRuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    enabled: bool = True
    metric: AlertMetric
    aggregation: AlertAggregation
    window_minutes: int = Field(default=15, ge=1, le=1440)
    threshold: float
    comparison: AlertComparison = AlertComparison.GT
    group_by: str | None = Field(default=None, pattern=r"^(model|agent_id|project_id)$")
    filter_model: str | None = None
    filter_agent_id: str | None = None
    severity: AlertSeverity = AlertSeverity.WARNING
    channel: AlertChannel
    target: str = Field(..., min_length=1, max_length=1024)
    cooldown_minutes: int = Field(default=15, ge=0, le=1440)


class AlertRuleOut(BaseModel):
    model_config = _BASE
    id: str
    organization_id: str
    name: str
    description: str | None
    enabled: bool
    metric: AlertMetric
    aggregation: AlertAggregation
    window_minutes: int
    threshold: float
    comparison: AlertComparison
    group_by: str | None
    filter_model: str | None
    filter_agent_id: str | None
    severity: AlertSeverity
    channel: AlertChannel
    target: str
    cooldown_minutes: int
    last_evaluated_at: datetime | None
    created_at: datetime


class AlertEventOut(BaseModel):
    model_config = _BASE
    id: str
    organization_id: str
    rule_id: str
    fired_at: datetime
    resolved_at: datetime | None
    state: AlertState
    metric_value: float
    threshold: float
    group_key: str | None
    delivered: bool
    delivery_error: str | None
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None


class AlertAcknowledgeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    acknowledged_by: str = Field(..., min_length=1, max_length=255)
    note: str | None = None

