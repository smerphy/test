/** OpenAI Chat Completions middleware. */

import type { PraetorClient, EvaluateOptions } from "../client.js";

interface FunctionCall {
  name: string;
  arguments: string; // JSON-encoded
}

interface ToolCall {
  id: string;
  type: "function";
  function: FunctionCall;
}

function parseArgs(raw: string | undefined): Record<string, unknown> {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

const DENY_TEMPLATE = { __praetor_blocked__: true } as const;

export function gateToolCalls(
  calls: ToolCall[],
  opts: { client: PraetorClient } & EvaluateOptions,
): ToolCall[] {
  const { client, ...evalOpts } = opts;
  return calls.map((call) => {
    const args = parseArgs(call.function.arguments);
    const result = client.evaluate(call.function.name, args, {
      ...evalOpts,
      toolUseId: call.id,
    });
    if (result.decision === "allow") return call;
    if (result.decision === "transform") {
      return {
        ...call,
        function: {
          ...call.function,
          arguments: JSON.stringify({ ...args, ...(result.suggested_transform ?? {}) }),
        },
      };
    }
    return {
      ...call,
      function: {
        ...call.function,
        arguments: JSON.stringify({
          ...DENY_TEMPLATE,
          policy_id: result.matched_policy_id,
          reason: result.reason,
          decision: result.decision,
        }),
      },
    };
  });
}
