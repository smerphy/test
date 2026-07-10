/**
 * Anthropic Messages API middleware.
 *
 * Walks `tool_use` content blocks; ALLOW passes through, TRANSFORM
 * merges the suggested args, DENY substitutes a `__ephorate_blocked__`
 * sentinel so the model can re-plan.
 */

import type { EphorateClient } from "../client.js";
import type { EvaluateOptions } from "../client.js";

interface ToolUseBlock {
  type: "tool_use";
  id: string;
  name: string;
  input: Record<string, unknown>;
}

type ContentBlock = ToolUseBlock | { type: string; [key: string]: unknown };

interface MessageLike {
  content: ContentBlock[];
  [key: string]: unknown;
}

const DENY_TEMPLATE = { __ephorate_blocked__: true } as const;

function isToolUse(block: ContentBlock): block is ToolUseBlock {
  return block.type === "tool_use";
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

export function gateToolUseBlocks(
  blocks: ContentBlock[],
  opts: { client: EphorateClient } & EvaluateOptions,
): ContentBlock[] {
  const { client, ...evalOpts } = opts;
  return blocks.map((block) => {
    if (!isToolUse(block)) return block;
    // Fail closed: a malformed block (non-string name, or input that is absent
    // or not a plain object) cannot be evaluated against what will execute, so
    // deny it rather than coerce input to `{}` and emit the original block.
    if (typeof block.name !== "string" || !isPlainObject(block.input)) {
      return {
        ...block,
        input: {
          ...DENY_TEMPLATE,
          policy_id: null,
          reason: "unevaluatable tool_use block (missing/invalid name or input)",
          decision: "deny",
        },
      };
    }
    const result = client.evaluate(block.name, block.input, {
      ...evalOpts,
      toolUseId: block.id,
    });
    if (result.decision === "allow") return block;
    if (result.decision === "transform") {
      return {
        ...block,
        input: { ...block.input, ...(result.suggested_transform ?? {}) },
      };
    }
    return {
      ...block,
      input: {
        ...DENY_TEMPLATE,
        policy_id: result.matched_policy_id,
        reason: result.reason,
        decision: result.decision,
      },
    };
  });
}

export function gateResponse<T extends MessageLike>(
  response: T,
  opts: { client: EphorateClient } & EvaluateOptions,
): T {
  return { ...response, content: gateToolUseBlocks(response.content, opts) };
}
