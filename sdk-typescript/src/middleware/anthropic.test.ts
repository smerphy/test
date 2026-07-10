import { describe, expect, it } from "vitest";
import { EphorateClient } from "../client.js";
import type { Policy } from "../types.js";
import { gateResponse, gateToolUseBlocks } from "./anthropic.js";

function client(policies: Policy[] = []) {
  return new EphorateClient({ policies, defaultAgentId: "agent-1" });
}

const tuBlock = (
  name: string,
  input: Record<string, unknown>,
  id = "toolu_1",
) => ({ type: "tool_use" as const, id, name, input });

describe("Anthropic middleware", () => {
  it("text blocks pass through", () => {
    const blocks = [{ type: "text", text: "hi" }];
    const out = gateToolUseBlocks(blocks, {
      client: client([
        { id: "p", effect: "allow", reason: "x", when: { op: "always" } },
      ]),
      sessionId: "s",
    });
    expect(out).toEqual(blocks);
  });

  it("fails CLOSED when name/input is missing or non-object", () => {
    const allowAll = () =>
      client([{ id: "p", effect: "allow", reason: "x", when: { op: "always" } }]);
    const bad = [
      { type: "tool_use" as const, id: "t", name: "http.get", input: ["x"] },
      { type: "tool_use" as const, id: "t", name: "http.get", input: "str" },
      { type: "tool_use" as const, id: "t", name: 123, input: { url: "x" } },
      { type: "tool_use" as const, id: "t", name: "http.get" }, // input absent
    ];
    for (const block of bad) {
      const out = gateToolUseBlocks([block as never], {
        client: allowAll(),
        sessionId: "s",
      });
      const first = out[0] as { input: Record<string, unknown> };
      expect(first.input.__ephorate_blocked__).toBe(true); // denied despite allow-all
      expect(first.input.decision).toBe("deny");
    }
  });

  it("ALLOW passes block unchanged", () => {
    const block = tuBlock("http.get", { url: "https://x" });
    const out = gateToolUseBlocks([block], {
      client: client([
        {
          id: "allow",
          effect: "allow",
          reason: "x",
          when: { op: "eq", path: "tool.name", value: "http.get" },
        },
      ]),
      sessionId: "s",
    });
    expect(out[0]).toEqual(block);
  });

  it("TRANSFORM merges suggested args", () => {
    const block = tuBlock("http.get", { url: "https://x", method: "GET" });
    const out = gateToolUseBlocks([block], {
      client: client([
        {
          id: "redact",
          effect: "transform",
          reason: "r",
          transform: { url: "<r>" },
          when: { op: "always" },
        },
      ]),
      sessionId: "s",
    });
    expect((out[0] as typeof block).input).toEqual({
      url: "<r>",
      method: "GET",
    });
  });

  it("DENY substitutes blocked sentinel", () => {
    const block = tuBlock("http.get", { url: "https://x" });
    const out = gateToolUseBlocks([block], {
      client: client([
        {
          id: "deny",
          effect: "deny",
          reason: "blocked",
          when: { op: "always" },
        },
      ]),
      sessionId: "s",
    });
    const gated = out[0] as typeof block;
    expect(gated.input.__ephorate_blocked__).toBe(true);
    expect(gated.input.policy_id).toBe("deny");
    expect(gated.name).toBe("http.get");
  });

  it("default-deny with no matching policy", () => {
    const block = tuBlock("http.get", { url: "https://x" });
    const out = gateToolUseBlocks([block], { client: client(), sessionId: "s" });
    expect((out[0] as typeof block).input.__ephorate_blocked__).toBe(true);
  });

  it("gateResponse round-trips a message-like object", () => {
    const response = {
      id: "msg_1",
      content: [{ type: "text", text: "hi" }, tuBlock("http.get", { url: "https://x" })],
    };
    const out = gateResponse(response, {
      client: client([
        { id: "d", effect: "deny", reason: "x", when: { op: "always" } },
      ]),
      sessionId: "s",
    });
    expect(out.id).toBe("msg_1");
    const blocked = out.content[1] as { input: Record<string, unknown> };
    expect(blocked.input.__ephorate_blocked__).toBe(true);
  });
});
