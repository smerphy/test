/** OpenAI Chat Completions middleware. */

import type { EphorateClient, EvaluateOptions } from "../client.js";

interface FunctionCall {
  name: string;
  arguments: string; // JSON-encoded
}

interface ToolCall {
  id: string;
  type: "function";
  function: FunctionCall;
}

/**
 * Parse tool-call arguments into an object.
 *
 * Returns `null` when arguments are *present but not a JSON object* (malformed
 * JSON, or a non-object like an array/scalar). The caller treats `null` as
 * fail-closed: we cannot evaluate the policy against the exact arguments that
 * will execute, so the call is denied rather than evaluated as an empty `{}`
 * and passed through. Absent/empty arguments legitimately mean "no arguments".
 */
function parseArgs(raw: string | undefined): Record<string, unknown> | null {
  if (!raw) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : null;
}

const DENY_TEMPLATE = { __ephorate_blocked__: true } as const;

export function gateToolCalls(
  calls: ToolCall[],
  opts: { client: EphorateClient } & EvaluateOptions,
): ToolCall[] {
  const { client, ...evalOpts } = opts;
  return calls.map((call) => {
    const args = parseArgs(call.function.arguments);
    // Fail closed: arguments present but unparseable / non-object cannot be
    // evaluated against the exact object that will execute — deny rather than
    // coerce to `{}` and emit the original (which would bypass arg-keyed denies).
    if (args === null) {
      return {
        ...call,
        function: {
          ...call.function,
          arguments: JSON.stringify({
            ...DENY_TEMPLATE,
            policy_id: null,
            reason: "unevaluatable tool call (invalid arguments)",
            decision: "deny",
          }),
        },
      };
    }
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
