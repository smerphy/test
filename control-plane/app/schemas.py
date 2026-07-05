"""Pydantic request / response schemas. Decoupled from ORM models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from praetor_engine.audit_hash import canonical_timestamp as _canonical_timestamp
from praetor_engine.types import Decision
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_serializer,
    model_validator,
)

from app.models import (
    TLP,
    AlertAggregation,
    AlertChannel,
    AlertComparison,
    AlertMetric,
    AlertSeverity,
    AlertState,
    ApprovalStatus,
    FeedFormat,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    IndicatorType,
    QuarantineSource,
    ReportStatus,
    Role,
    RolloutState,
)
from app.models.finding import risk_score as _risk_score

_BASE = ConfigDict(from_attributes=True, extra="forbid")


class OrganizationOut(BaseModel):
    model_config = _BASE
    id: str
    name: str
    slug: str
    approval_webhook_url: str | None = None
    auto_quarantine: bool = False
    finding_webhook_url: str | None = None
    finding_min_severity: str = "high"


class OrganizationUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Slack-compatible incoming-webhook URL for pending-approval
    # notifications. Pass null to disable.
    approval_webhook_url: str | None = Field(default=None, max_length=1024)
    # Enable EDR auto-response: CRITICAL findings auto-quarantine their entity.
    auto_quarantine: bool | None = None
    # Forward new findings (>= finding_min_severity) to this webhook / SIEM.
    finding_webhook_url: str | None = Field(default=None, max_length=1024)
    finding_min_severity: FindingSeverity | None = None


class UserOut(BaseModel):
    model_config = _BASE
    id: str
    email: str
    name: str | None = None
    role: Role
    organization_id: str
    created_at: datetime


class UserUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role | None = None
    name: str | None = Field(default=None, max_length=255)


class WhoAmIOut(BaseModel):
    """The calling principal's identity + effective RBAC role.

    Works for both credential paths, so the web console can gate its UI on
    the role even when it authenticates via a shared API key (``kind`` is
    ``api_key`` and the user fields are null in that case).
    """

    model_config = ConfigDict(extra="forbid")
    kind: str
    role: Role
    organization_id: str
    organization_slug: str
    user_id: str | None = None
    email: str | None = None
    name: str | None = None


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
    # Bound the bundle size: caps parser memory/CPU and the blast radius of a
    # YAML alias-expansion ("billion laughs") bundle. 256 KiB is far above any
    # realistic policy bundle.
    yaml_text: str = Field(..., min_length=1, max_length=256 * 1024)
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


# ----------------------------------------------------------------
# Findings (SIEM / EDR detections)
# ----------------------------------------------------------------


class FindingOut(BaseModel):
    model_config = _BASE
    id: str
    rule_id: str
    title: str
    severity: FindingSeverity
    category: FindingCategory
    status: FindingStatus
    source: str
    impact: str
    fidelity: float
    agent_id: str | None
    session_id: str | None
    count: int
    first_seen: datetime
    last_seen: datetime
    evidence: dict[str, Any]
    atlas_technique: str | None
    owasp_llm: str | None
    assignee: str | None
    note: str | None
    resolved_at: datetime | None
    resolved_by: str | None
    created_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_score(self) -> float:
        """Composite priority = severity x impact x fidelity (0-100)."""
        return _risk_score(self.severity, self.impact, self.fidelity)


class FindingReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Free-form security observation (untrusted text; scored, never executed).
    observation: str = Field(..., min_length=1, max_length=8000)
    agent_id: str | None = Field(default=None, max_length=255)
    session_id: str | None = Field(default=None, max_length=255)
    category: FindingCategory | None = None
    suggested_severity: FindingSeverity | None = None
    context: str = Field(default="", max_length=4000)
    evidence: dict[str, Any] = Field(default_factory=dict)


class FindingUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: FindingStatus | None = None
    assignee: str | None = Field(default=None, max_length=255)
    note: str | None = Field(default=None, max_length=4000)
    resolved_by: str | None = Field(default=None, max_length=255)


class DetectionRuleSpec(BaseModel):
    """A bounded, structured match over audit events (no code, no regex).

    All present conditions must hold (AND). Matching events are grouped by
    `group_by`; a group meeting `threshold` raises a finding.
    """

    model_config = ConfigDict(extra="forbid")
    decision: str | None = Field(default=None, max_length=32)
    matched_policy_prefix: str | None = Field(default=None, max_length=255)
    matched_policy_contains: str | None = Field(default=None, max_length=255)
    tool_name: str | None = Field(default=None, max_length=255)
    group_by: Literal["agent", "session"] = "session"
    threshold: int = Field(default=1, ge=1, le=100_000)
    window_minutes: int = Field(default=60, ge=1, le=1440)

    @model_validator(mode="after")
    def _require_a_condition(self) -> DetectionRuleSpec:
        if not any(
            [
                self.decision,
                self.matched_policy_prefix,
                self.matched_policy_contains,
                self.tool_name,
            ]
        ):
            raise ValueError("spec must set at least one match condition")
        return self


class DetectionRuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    description: str | None = Field(default=None, max_length=1024)
    enabled: bool = True
    severity: FindingSeverity
    category: FindingCategory
    spec: DetectionRuleSpec
    atlas_technique: str | None = Field(default=None, max_length=64)
    owasp_llm: str | None = Field(default=None, max_length=32)


class DetectionRuleOut(BaseModel):
    model_config = _BASE
    id: str
    name: str
    description: str | None
    enabled: bool
    severity: FindingSeverity
    category: FindingCategory
    spec: dict[str, Any]
    atlas_technique: str | None
    owasp_llm: str | None
    created_at: datetime


# ----------------------------------------------------------------
# Fleet / sensor management
# ----------------------------------------------------------------


class HeartbeatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1, max_length=255)
    name: str | None = Field(default=None, max_length=255)
    agent_version: str | None = Field(default=None, max_length=64)
    sdk_version: str | None = Field(default=None, max_length=64)


class AgentOut(BaseModel):
    model_config = _BASE
    id: str
    agent_id: str
    name: str | None
    agent_version: str | None
    sdk_version: str | None
    first_seen: datetime
    last_seen: datetime
    health: str


# ----------------------------------------------------------------
# Quarantines (EDR response)
# ----------------------------------------------------------------


class QuarantineCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str | None = Field(default=None, max_length=255)
    session_id: str | None = Field(default=None, max_length=255)
    reason: str = Field(..., min_length=1, max_length=1024)
    created_by: str | None = Field(default=None, max_length=255)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def _require_entity(self) -> QuarantineCreateIn:
        if not self.agent_id and not self.session_id:
            raise ValueError("at least one of agent_id or session_id is required")
        return self


class QuarantineOut(BaseModel):
    model_config = _BASE
    id: str
    agent_id: str | None
    session_id: str | None
    reason: str
    source: QuarantineSource
    finding_id: str | None
    active: bool
    expires_at: datetime | None
    created_by: str | None
    created_at: datetime
    lifted_at: datetime | None
    lifted_by: str | None


class QuarantineCheckOut(BaseModel):
    quarantined: bool
    reason: str | None = None
    quarantine_id: str | None = None


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



# ----------------------------------------------------------------
# Threat intelligence
# ----------------------------------------------------------------


class ThreatFeedIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    # Null URL = a manually curated feed.
    url: str | None = Field(default=None, max_length=2048)
    format: FeedFormat
    default_indicator_type: IndicatorType | None = None
    auth_header: str | None = Field(default=None, max_length=1024)
    enabled: bool = True
    tlp: TLP = TLP.AMBER
    default_confidence: int = Field(default=50, ge=0, le=100)
    default_severity: FindingSeverity = FindingSeverity.HIGH
    refresh_minutes: int = Field(default=60, ge=5, le=10080)


class ThreatFeedUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    url: str | None = Field(default=None, max_length=2048)
    format: FeedFormat | None = None
    default_indicator_type: IndicatorType | None = None
    auth_header: str | None = Field(default=None, max_length=1024)
    enabled: bool | None = None
    tlp: TLP | None = None
    default_confidence: int | None = Field(default=None, ge=0, le=100)
    default_severity: FindingSeverity | None = None
    refresh_minutes: int | None = Field(default=None, ge=5, le=10080)


class ThreatFeedOut(BaseModel):
    model_config = _BASE
    id: str
    organization_id: str
    name: str
    description: str | None
    url: str | None
    format: str
    default_indicator_type: str | None
    enabled: bool
    tlp: str
    default_confidence: int
    default_severity: str
    refresh_minutes: int
    last_synced_at: datetime | None
    last_status: str
    last_error: str | None
    indicator_count: int
    created_at: datetime


class ThreatFeedSyncResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    created: int
    updated: int
    status: str
    error: str | None = None


class ThreatIndicatorIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: IndicatorType
    value: str = Field(..., min_length=1, max_length=1024)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: FindingSeverity = FindingSeverity.HIGH
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    description: str | None = Field(default=None, max_length=2000)
    tlp: TLP = TLP.AMBER
    expires_at: datetime | None = None


class ThreatIndicatorOut(BaseModel):
    model_config = _BASE
    id: str
    organization_id: str
    feed_id: str | None
    type: str
    value: str
    confidence: int
    severity: str
    tags: list[str]
    references: list[str]
    description: str | None
    tlp: str
    enabled: bool
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    created_at: datetime


class TaxiiDiscoverIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # TAXII 2.1 API root URL, e.g. https://taxii.example.com/api1
    url: str = Field(..., min_length=1, max_length=2048)
    auth_header: str | None = Field(default=None, max_length=1024)


class TaxiiCollectionOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title: str | None = None
    description: str | None = None
    can_read: bool = True
    media_types: list[str] = Field(default_factory=list)
    # Ready-to-use collection objects endpoint to configure a feed with.
    objects_url: str


# ----------------------------------------------------------------
# AI-native advisory
# ----------------------------------------------------------------


class AIConfigOut(BaseModel):
    model_config = _BASE
    ai_enabled: bool
    ai_mode: str
    ai_provider: str
    ai_model: str
    ai_base_url: str | None = None
    ai_monthly_budget_usd: float | None = None
    # The key itself is never returned; only whether one is stored.
    ai_key_set: bool = False


class AIConfigUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ai_enabled: bool | None = None
    ai_mode: Literal["advisory", "enforce"] | None = None
    ai_provider: Literal["anthropic", "openai_compat"] | None = None
    ai_model: str | None = Field(default=None, max_length=128)
    ai_base_url: str | None = Field(default=None, max_length=1024)
    ai_monthly_budget_usd: float | None = Field(default=None, ge=0)
    # Write-only. Provide to set the key; empty string clears it.
    ai_api_key: str | None = Field(default=None, max_length=1024)


class AIUsageOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    month: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    call_count: int
    budget_usd: float | None = None
    over_budget: bool = False


class AssessIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(..., min_length=1, max_length=255)
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = Field(default=None, max_length=255)
    session_id: str | None = Field(default=None, max_length=255)
    deterministic_decision: Literal[
        "allow", "deny", "require_approval", "transform"
    ] = "require_approval"
    reason: str = Field(default="", max_length=1024)
    matched_policy_id: str | None = Field(default=None, max_length=255)


class AgentOpinionOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str
    decision: str
    confidence: float
    rationale: str


class AssessOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recommended_decision: str
    final_decision: str
    mode: str
    confidence: float
    rationale: str
    opinions: list[AgentOpinionOut] = Field(default_factory=list)
    provider: str
    model: str
    error: str | None = None


class RuleSuggestionOut(BaseModel):
    model_config = _BASE
    id: str
    title: str
    rationale: str
    severity: str
    category: str
    spec: dict[str, Any]
    atlas_technique: str | None
    owasp_llm: str | None
    confidence: float
    source: str
    status: str
    reviewed_by: str | None
    created_rule_id: str | None
    created_at: datetime


class SuggestionReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reviewed_by: str | None = Field(default=None, max_length=255)


# ----------------------------------------------------------------
# Privacy / data governance
# ----------------------------------------------------------------


class EraseSubjectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # The identifier to erase (email, name, user id, …).
    subject: str = Field(..., min_length=2, max_length=512)
    # Preview the blast radius without mutating anything.
    dry_run: bool = False


class EraseSubjectOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str
    dry_run: bool
    findings_scrubbed: int
    approvals_scrubbed: int
    occurrences: int
    # Audit events reference the subject but are hash-chained (immutable here).
    audit_events_referencing: int


class AccessLogOut(BaseModel):
    model_config = _BASE
    id: str
    actor: str
    actor_kind: str
    resource: str
    action: str
    method: str
    path: str
    source_ip: str | None
    detail: dict[str, Any]
    created_at: datetime


class AuditAnchorOut(BaseModel):
    model_config = _BASE
    id: str
    chain_count: int
    event_count: int
    root: str
    prev_anchor_hash: str
    anchor_hash: str
    published_to: str | None
    created_at: datetime


class AuditVerifyOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    anchored: bool
    tampered: bool
    anchor_hash: str | None = None
    anchored_at: str | None = None
    chains_checked: int = 0
    mismatches: list[dict[str, Any]] = Field(default_factory=list)
