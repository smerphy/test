import { Evaluator } from "./evaluator.js";
import { NullAuditSink, type AuditSink } from "./audit.js";
import { PolicyDenied } from "./errors.js";
import type { DecisionResult, Policy, PolicyInput } from "./types.js";

export interface EvaluateOptions {
  sessionId: string;
  agentId?: string;
  agentName?: string;
  agentVersion?: string;
  toolUseId?: string;
  context?: Record<string, unknown>;
}

export class EphorateClient {
  private readonly evaluator: Evaluator;
  private readonly audit: AuditSink;
  private readonly defaultAgentId?: string;

  constructor(opts: {
    policies: Policy[];
    auditSink?: AuditSink;
    defaultAgentId?: string;
  }) {
    this.evaluator = new Evaluator(opts.policies);
    this.audit = opts.auditSink ?? new NullAuditSink();
    this.defaultAgentId = opts.defaultAgentId;
  }

  get policies(): readonly Policy[] {
    return (this.evaluator as unknown as { policies: readonly Policy[] }).policies;
  }

  evaluate(
    toolName: string,
    toolArguments: Record<string, unknown>,
    opts: EvaluateOptions,
  ): DecisionResult {
    const agentId = opts.agentId ?? this.defaultAgentId;
    if (!agentId) {
      throw new Error("agentId must be passed or defaultAgentId set on the client");
    }
    const input: PolicyInput = {
      agent: {
        id: agentId,
        name: opts.agentName ?? null,
        version: opts.agentVersion ?? null,
      },
      tool: {
        name: toolName,
        arguments: toolArguments,
        tool_use_id: opts.toolUseId ?? null,
      },
      session: { id: opts.sessionId },
      context: opts.context ?? {},
    };
    const result = this.evaluator.evaluate(input);
    this.audit.record(input, result);
    return result;
  }

  /** Evaluate and return final (possibly transformed) args, or throw. */
  enforce(
    toolName: string,
    toolArguments: Record<string, unknown>,
    opts: EvaluateOptions,
  ): Record<string, unknown> {
    const result = this.evaluate(toolName, toolArguments, opts);
    if (result.decision === "allow") return toolArguments;
    if (result.decision === "transform") {
      return { ...toolArguments, ...(result.suggested_transform ?? {}) };
    }
    throw new PolicyDenied(result);
  }
}
