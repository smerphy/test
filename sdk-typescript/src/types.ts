/**
 * Core types — mirror the engine's PolicyInput / Decision /
 * DecisionResult / Predicate / Policy shape.
 *
 * These are the wire types: shipping over HTTP, serializing in the
 * audit log, etc. They are kept in lock-step with the engine's
 * `engine/schemas/*.schema.json` outputs.
 */

export type Decision = "allow" | "deny" | "transform" | "require_approval";

export interface AgentInfo {
  id: string;
  name?: string | null;
  version?: string | null;
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
  tool_use_id?: string | null;
}

export interface SessionInfo {
  id: string;
  started_at?: string | null;
  parent_agent_ids?: string[];
}

export interface PolicyInput {
  agent: AgentInfo;
  tool: ToolCall;
  session: SessionInfo;
  context?: Record<string, unknown>;
}

export interface DecisionResult {
  decision: Decision;
  reason: string;
  matched_policy_id?: string | null;
  suggested_transform?: Record<string, unknown> | null;
}

/* ---------- Predicates ---------- */

type Scalar = string | number | boolean | null;

export type Predicate =
  | { op: "always" }
  | { op: "eq"; path: string; value: Scalar }
  | { op: "in"; path: string; values: Scalar[] }
  | { op: "matches"; path: string; pattern: string }
  | { op: "and"; clauses: Predicate[] }
  | { op: "or"; clauses: Predicate[] }
  | { op: "not"; clause: Predicate };

export interface Policy {
  id: string;
  effect: Decision;
  when: Predicate;
  reason: string;
  transform?: Record<string, unknown> | null;
  metadata?: Record<string, string>;
}
