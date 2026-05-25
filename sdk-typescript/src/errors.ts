import type { DecisionResult } from "./types.js";

export class PraetorError extends Error {}

export class PolicyDenied extends PraetorError {
  readonly decision: DecisionResult;
  constructor(decision: DecisionResult) {
    super(
      `tool call blocked: ${decision.decision} (policy=${decision.matched_policy_id}; reason=${decision.reason})`,
    );
    this.decision = decision;
    this.name = "PolicyDenied";
  }
}

export class ApprovalTimeout extends PraetorError {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalTimeout";
  }
}

export class AuditError extends PraetorError {
  constructor(message: string) {
    super(message);
    this.name = "AuditError";
  }
}
