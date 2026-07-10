import { describe, expect, it } from "vitest";
import { EphorateClient } from "../client.js";
import type { Policy } from "../types.js";
import { gateToolCalls } from "./openai.js";

function client(policies: Policy[] = []) {
  return new EphorateClient({ policies, defaultAgentId: "agent-1" });
}

const tc = (name: string, args: Record<string, unknown>, id = "call_1") => ({
  id,
  type: "function" as const,
  function: { name, arguments: JSON.stringify(args) },
});

describe("OpenAI middleware", () => {
  it("ALLOW passes through unchanged", () => {
    const call = tc("http.get", { url: "https://x" });
    const out = gateToolCalls([call], {
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
    expect(out[0]).toEqual(call);
  });

  it("TRANSFORM re-serializes arguments", () => {
    const call = tc("http.get", { url: "https://x", method: "GET" });
    const out = gateToolCalls([call], {
      client: client([
        {
          id: "redact",
          effect: "transform",
          reason: "x",
          transform: { url: "<r>" },
          when: { op: "always" },
        },
      ]),
      sessionId: "s",
    });
    expect(JSON.parse(out[0]!.function.arguments)).toEqual({
      url: "<r>",
      method: "GET",
    });
  });

  it("DENY emits blocked payload", () => {
    const call = tc("http.get", { url: "https://x" });
    const out = gateToolCalls([call], {
      client: client([
        { id: "d", effect: "deny", reason: "x", when: { op: "always" } },
      ]),
      sessionId: "s",
    });
    const payload = JSON.parse(out[0]!.function.arguments);
    expect(payload.__ephorate_blocked__).toBe(true);
    expect(payload.policy_id).toBe("d");
  });

  it("fails CLOSED on malformed/non-object arguments (does not pass through)", () => {
    const allowAll = () =>
      client([{ id: "allow", effect: "allow", reason: "x", when: { op: "always" } }]);
    for (const bad of ["{not json", "[1,2,3]", "42", '"str"']) {
      const call = { id: "x", type: "function" as const, function: { name: "http.get", arguments: bad } };
      const out = gateToolCalls([call], { client: allowAll(), sessionId: "s" });
      const payload = JSON.parse(out[0]!.function.arguments);
      expect(payload.__ephorate_blocked__).toBe(true); // denied despite allow-all
      expect(payload.decision).toBe("deny");
    }
  });

  it("absent/empty arguments evaluate as no-args and pass through on allow", () => {
    const call = { id: "x", type: "function" as const, function: { name: "http.get", arguments: "" } };
    const out = gateToolCalls([call], {
      client: client([
        { id: "allow", effect: "allow", reason: "x", when: { op: "always" } },
      ]),
      sessionId: "s",
    });
    expect(out[0]).toEqual(call);
  });
});
