/**
 * Typed client for the Praetor control plane HTTP API.
 *
 * Reads `PRAETOR_CONTROL_PLANE_URL` and `PRAETOR_API_KEY` from the
 * environment. The org slug is sourced from `PRAETOR_ORG_SLUG` (single-
 * tenant MVP); multi-tenancy will switch to a session-derived value.
 */

const BASE_URL =
  process.env.PRAETOR_CONTROL_PLANE_URL ?? "http://localhost:8000";
const API_KEY = process.env.PRAETOR_API_KEY ?? "";
const ORG_SLUG = process.env.PRAETOR_ORG_SLUG ?? "acme";

export interface Project {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
}

export interface PolicyBundle {
  id: string;
  project_id: string;
  name: string;
  description: string | null;
  version_count: number;
}

export interface PolicyVersionSummary {
  id: string;
  bundle_id: string;
  version_number: number;
  policy_count: number;
  author_email: string | null;
  notes: string | null;
  created_at: string;
}

export interface PolicyVersion extends PolicyVersionSummary {
  yaml_text: string;
}

export type Decision = "allow" | "deny" | "transform" | "require_approval";

export interface AuditEvent {
  id: string;
  organization_id: string;
  seq: number;
  timestamp: string;
  agent_id: string;
  session_id: string;
  tool_name: string;
  tool_use_id: string | null;
  tool_arguments: Record<string, unknown>;
  decision: Decision;
  reason: string;
  matched_policy_id: string | null;
  suggested_transform: Record<string, unknown> | null;
  context: Record<string, unknown>;
  evaluator_version: string;
  prev_hash: string;
  hash: string;
}

export interface ApprovalRequest {
  id: string;
  agent_id: string;
  session_id: string;
  tool_name: string;
  tool_arguments: Record<string, unknown>;
  policy_id: string | null;
  reason: string;
  status: "pending" | "approved" | "denied" | "expired";
  resolved_at: string | null;
  resolved_by: string | null;
  created_at: string;
}

export interface ComplianceReport {
  id: string;
  framework: string;
  period_start: string;
  period_end: string;
  status: "pending" | "generating" | "complete" | "failed";
  summary: {
    framework: string;
    period_start: string;
    period_end: string;
    controls: string[];
    decision_counts: Record<Decision, number>;
    total_evaluations: number;
    deny_rate: number;
    approval_rate: number;
  } | null;
  error: string | null;
  created_at: string;
}

type Method = "GET" | "POST" | "PATCH";

async function call<T>(
  path: string,
  init: { method?: Method; body?: unknown } = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "X-Org-Slug": ORG_SLUG,
    Accept: "application/json",
  };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  if (init.body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(`${BASE_URL}${path}`, {
    method: init.method ?? "GET",
    headers,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    cache: "no-store",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status} ${path}: ${text}`);
  }
  return (await res.json()) as T;
}

export const api = {
  listProjects: () => call<Project[]>("/projects"),
  listBundles: (projectId: string) =>
    call<PolicyBundle[]>(`/projects/${projectId}/bundles`),
  listVersions: (bundleId: string) =>
    call<PolicyVersionSummary[]>(`/bundles/${bundleId}/versions`),
  getVersion: (versionId: string) =>
    call<PolicyVersion>(`/versions/${versionId}`),
  createVersion: (bundleId: string, body: { yaml_text: string; notes?: string }) =>
    call<PolicyVersion>(`/bundles/${bundleId}/versions`, {
      method: "POST",
      body,
    }),
  searchAudit: (params: Record<string, string | undefined>) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") qs.set(k, v);
    }
    const path = qs.toString()
      ? `/audit/events?${qs.toString()}`
      : "/audit/events";
    return call<AuditEvent[]>(path);
  },
  listApprovals: (status: ApprovalRequest["status"] = "pending") =>
    call<ApprovalRequest[]>(`/approvals?status=${status}`),
  resolveApproval: (id: string, approved: boolean, resolved_by?: string) =>
    call<ApprovalRequest>(`/approvals/${id}/resolve`, {
      method: "POST",
      body: { approved, resolved_by },
    }),
  listReports: () => call<ComplianceReport[]>("/reports/compliance"),
  createReport: (body: {
    framework: string;
    period_start: string;
    period_end: string;
  }) =>
    call<ComplianceReport>("/reports/compliance", { method: "POST", body }),

  aggregateMetrics: (params: Record<string, string | undefined>) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") qs.set(k, v);
    }
    const path = qs.toString()
      ? `/metrics/aggregate?${qs.toString()}`
      : "/metrics/aggregate";
    return call<MetricAggregateResponse>(path);
  },
  listAlertRules: () => call<AlertRule[]>("/alerts/rules"),
  createAlertRule: (body: Partial<AlertRule>) =>
    call<AlertRule>("/alerts/rules", { method: "POST", body }),
  evaluateAlertRule: (id: string) =>
    call<AlertEvent[]>(`/alerts/rules/${id}/evaluate`, { method: "POST" }),
  listAlertEvents: (limit = 100) =>
    call<AlertEvent[]>(`/alerts/events?limit=${limit}`),
  acknowledgeAlert: (id: string, acknowledged_by: string, note?: string) =>
    call<AlertEvent>(`/alerts/events/${id}/acknowledge`, {
      method: "POST",
      body: { acknowledged_by, note },
    }),

  // SIEM / EDR
  getOverview: () => call<SecurityOverview>("/overview"),
  listFindings: (params: Record<string, string | undefined> = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") qs.set(k, v);
    }
    const path = qs.toString() ? `/findings?${qs.toString()}` : "/findings";
    return call<Finding[]>(path);
  },
  updateFinding: (id: string, body: Partial<{ status: string; assignee: string; note: string; resolved_by: string }>) =>
    call<Finding>(`/findings/${id}`, { method: "PATCH", body }),
  listAgents: () => call<Agent[]>("/agents"),
  listQuarantines: () => call<Quarantine[]>("/quarantines/active"),
  liftQuarantine: (id: string) =>
    call<Quarantine>(`/quarantines/${id}/lift`, { method: "POST" }),

  // RBAC
  whoami: () => call<WhoAmI>("/whoami"),
  listMembers: () => call<Member[]>("/users"),
  updateMember: (id: string, body: { role?: Role; name?: string }) =>
    call<Member>(`/users/${id}`, { method: "PATCH", body }),

  // Threat intelligence
  listFeeds: () => call<ThreatFeed[]>("/threat/feeds"),
  createFeed: (body: {
    name: string;
    format: string;
    url?: string;
    default_indicator_type?: string;
    description?: string;
  }) => call<ThreatFeed>("/threat/feeds", { method: "POST", body }),
  syncFeed: (id: string) =>
    call<FeedSyncResult>(`/threat/feeds/${id}/sync`, { method: "POST" }),
  listIndicators: (params: Record<string, string | undefined> = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") qs.set(k, v);
    }
    const path = qs.toString()
      ? `/threat/indicators?${qs.toString()}`
      : "/threat/indicators";
    return call<ThreatIndicator[]>(path);
  },
  createIndicator: (body: {
    type: string;
    value: string;
    severity?: string;
    confidence?: number;
    description?: string;
  }) => call<ThreatIndicator>("/threat/indicators", { method: "POST", body }),
};

export type IndicatorType =
  | "domain"
  | "ip"
  | "url"
  | "sha256"
  | "md5"
  | "email"
  | "tool_name"
  | "package"
  | "prompt_signature"
  | "regex";

export type FeedFormat = "json" | "csv" | "plaintext" | "stix" | "misp";

export interface ThreatFeed {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  url: string | null;
  format: FeedFormat;
  default_indicator_type: IndicatorType | null;
  enabled: boolean;
  tlp: string;
  default_confidence: number;
  default_severity: string;
  refresh_minutes: number;
  last_synced_at: string | null;
  last_status: string;
  last_error: string | null;
  indicator_count: number;
  created_at: string;
}

export interface FeedSyncResult {
  created: number;
  updated: number;
  status: string;
  error: string | null;
}

export interface ThreatIndicator {
  id: string;
  organization_id: string;
  feed_id: string | null;
  type: IndicatorType;
  value: string;
  confidence: number;
  severity: FindingSeverity;
  tags: string[];
  references: string[];
  description: string | null;
  tlp: string;
  enabled: boolean;
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
  created_at: string;
}

export type Role = "viewer" | "analyst" | "admin" | "owner";

export interface WhoAmI {
  kind: "user" | "api_key";
  role: Role;
  organization_id: string;
  organization_slug: string;
  user_id: string | null;
  email: string | null;
  name: string | null;
}

export interface Member {
  id: string;
  email: string;
  name: string | null;
  role: Role;
  organization_id: string;
  created_at: string;
}

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "triaging" | "resolved" | "false_positive";

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  severity: FindingSeverity;
  category: string;
  status: FindingStatus;
  agent_id: string | null;
  session_id: string | null;
  count: number;
  first_seen: string;
  last_seen: string;
  evidence: Record<string, unknown>;
  atlas_technique: string | null;
  owasp_llm: string | null;
  assignee: string | null;
  note: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  created_at: string;
}

export interface SecurityOverview {
  findings: {
    open_total: number;
    critical_open: number;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
  };
  quarantines: { active: number };
  approvals: { pending: number };
  activity_24h: { decisions: Record<string, number>; total: number };
}

export interface Agent {
  id: string;
  agent_id: string;
  name: string | null;
  agent_version: string | null;
  sdk_version: string | null;
  first_seen: string;
  last_seen: string;
  health: string;
}

export interface Quarantine {
  id: string;
  agent_id: string | null;
  session_id: string | null;
  reason: string;
  source: string;
  finding_id: string | null;
  active: boolean;
  expires_at: string | null;
  created_by: string | null;
  created_at: string;
  lifted_at: string | null;
  lifted_by: string | null;
}

export interface MetricBucket {
  bucket_start: string;
  request_count: number;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cost_usd: number;
  error_count: number;
  avg_duration_ms: number;
}

export interface MetricAggregateResponse {
  bucket_size_minutes: number;
  group_by: string | null;
  buckets: MetricBucket[];
  by_group: Record<string, MetricBucket[]>;
}

export type AlertMetric =
  | "cost_usd"
  | "input_tokens"
  | "output_tokens"
  | "total_tokens"
  | "duration_ms"
  | "request_count"
  | "error_count"
  | "error_rate"
  | "deny_count";

export type AlertAggregation =
  | "sum" | "avg" | "p50" | "p95" | "p99" | "max" | "count" | "rate";

export type AlertComparison = "gt" | "gte" | "lt" | "lte";

export type AlertSeverity = "info" | "warning" | "critical";

export type AlertChannel = "slack" | "pagerduty" | "webhook" | "email";

export type AlertState = "firing" | "acknowledged" | "resolved";

export interface AlertRule {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  metric: AlertMetric;
  aggregation: AlertAggregation;
  window_minutes: number;
  threshold: number;
  comparison: AlertComparison;
  group_by: string | null;
  filter_model: string | null;
  filter_agent_id: string | null;
  severity: AlertSeverity;
  channel: AlertChannel;
  target: string;
  cooldown_minutes: number;
  last_evaluated_at: string | null;
  created_at: string;
}

export interface AlertEvent {
  id: string;
  organization_id: string;
  rule_id: string;
  fired_at: string;
  resolved_at: string | null;
  state: AlertState;
  metric_value: number;
  threshold: number;
  group_key: string | null;
  delivered: boolean;
  delivery_error: string | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
}
