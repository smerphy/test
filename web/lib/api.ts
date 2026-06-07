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

type Method = "GET" | "POST";

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
};

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

export type AlertState = "firing" | "resolved";

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
}
