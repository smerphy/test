import type { DecisionResult } from "./types.js";

export class EphorateError extends Error {}

export class PolicyDenied extends EphorateError {
  readonly decision: DecisionResult;
  constructor(decision: DecisionResult) {
    super(
      `tool call blocked: ${decision.decision} (policy=${decision.matched_policy_id}; reason=${decision.reason})`,
    );
    this.decision = decision;
    this.name = "PolicyDenied";
  }
}

export class ApprovalTimeout extends EphorateError {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalTimeout";
  }
}

export class AuditError extends EphorateError {
  constructor(message: string) {
    super(message);
    this.name = "AuditError";
  }
}
