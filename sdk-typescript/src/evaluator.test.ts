import { describe, expect, it } from "vitest";
import { Evaluator } from "./evaluator.js";
import type { Policy, PolicyInput } from "./types.js";

function input(toolName = "http.get"): PolicyInput {
  return {
    agent: { id: "agent-1" },
    tool: { name: toolName, arguments: { url: "https://example.com" } },
    session: { id: "sess-1" },
  };
}

describe("Evaluator contract", () => {
  it("default-denies on empty bundle", () => {
    const r = new Evaluator([]).evaluate(input());
    expect(r.decision).toBe("deny");
    expect(r.matched_policy_id).toBeNull();
  });

  it("single allow match", () => {
    const p: Policy = {
      id: "p1",
      effect: "allow",
      reason: "ok",
      when: { op: "eq", path: "tool.name", value: "http.get" },
    };
    const r = new Evaluator([p]).evaluate(input());
    expect(r.decision).toBe("allow");
    expect(r.matched_policy_id).toBe("p1");
  });

  it("deny beats allow", () => {
    const allow: Policy = { id: "a", effect: "allow", reason: "allow", when: { op: "always" } };
    const deny: Policy = {
      id: "d",
      effect: "deny",
      reason: "no",
      when: { op: "eq", path: "tool.name", value: "http.get" },
    };
    const r = new Evaluator([allow, deny]).evaluate(input());
    expect(r.decision).toBe("deny");
    expect(r.matched_policy_id).toBe("d");
  });

  it("require_approval beats transform and allow", () => {
    const policies: Policy[] = [
      { id: "allow", effect: "allow", reason: "x", when: { op: "always" } },
      {
        id: "trans",
        effect: "transform",
        reason: "y",
        transform: { url: "<r>" },
        when: { op: "eq", path: "tool.name", value: "http.get" },
      },
      {
        id: "approve",
        effect: "require_approval",
        reason: "z",
        when: { op: "eq", path: "tool.name", value: "http.get" },
      },
    ];
    const r = new Evaluator(policies).evaluate(input());
    expect(r.decision).toBe("require_approval");
    expect(r.matched_policy_id).toBe("approve");
  });

  it("transform carries replacement", () => {
    const p: Policy = {
      id: "redact",
      effect: "transform",
      reason: "x",
      transform: { url: "<r>" },
      when: { op: "always" },
    };
    const r = new Evaluator([p]).evaluate(input());
    expect(r.decision).toBe("transform");
    expect(r.suggested_transform).toEqual({ url: "<r>" });
  });

  it("first-match-wins within precedence tier", () => {
    const policies: Policy[] = [
      { id: "deny-a", effect: "deny", reason: "1st", when: { op: "always" } },
      { id: "deny-b", effect: "deny", reason: "2nd", when: { op: "always" } },
    ];
    const r = new Evaluator(policies).evaluate(input());
    expect(r.matched_policy_id).toBe("deny-a");
  });

  it("missing path -> false (default deny)", () => {
    const p: Policy = {
      id: "p",
      effect: "allow",
      reason: "x",
      when: { op: "eq", path: "agent.nonexistent", value: "z" },
    };
    const r = new Evaluator([p]).evaluate(input());
    expect(r.decision).toBe("deny");
    expect(r.matched_policy_id).toBeNull();
  });

  it("in / matches / and / or / not", () => {
    const p: Policy = {
      id: "p",
      effect: "allow",
      reason: "x",
      when: {
        op: "and",
        clauses: [
          { op: "in", path: "tool.name", values: ["http.get", "http.post"] },
          { op: "matches", path: "tool.arguments.url", pattern: "^https://" },
          { op: "not", clause: { op: "eq", path: "agent.id", value: "blocked" } },
        ],
      },
    };
    const r = new Evaluator([p]).evaluate(input());
    expect(r.decision).toBe("allow");
  });
});
