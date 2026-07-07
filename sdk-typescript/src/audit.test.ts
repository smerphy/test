import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { GENESIS_HASH, JsonlAuditSink, verifyChain } from "./audit.js";
import { AuditError } from "./errors.js";
import type { DecisionResult, PolicyInput } from "./types.js";

function input(): PolicyInput {
  return {
    agent: { id: "agent-1" },
    tool: { name: "http.get", arguments: { url: "https://x" } },
    session: { id: "s1" },
  };
}

function allow(): DecisionResult {
  return { decision: "allow", reason: "ok", matched_policy_id: "p1" };
}

describe("JsonlAuditSink", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ephorate-audit-"));
  });
  afterEach(() => {
    // tmp dirs are cleaned by the OS; nothing to do.
  });

  it("first event chains from genesis", () => {
    const sink = new JsonlAuditSink(join(dir, "audit.jsonl"));
    const ev = sink.record(input(), allow());
    expect(ev.seq).toBe(0);
    expect(ev.prev_hash).toBe(GENESIS_HASH);
    expect(ev.hash).not.toBe(GENESIS_HASH);
  });

  it("chain advances across appends", () => {
    const sink = new JsonlAuditSink(join(dir, "audit.jsonl"));
    const e0 = sink.record(input(), allow());
    const e1 = sink.record(input(), allow());
    expect(e1.seq).toBe(1);
    expect(e1.prev_hash).toBe(e0.hash);
  });

  it("resumes from tail on restart", () => {
    const path = join(dir, "audit.jsonl");
    const s1 = new JsonlAuditSink(path);
    s1.record(input(), allow());
    s1.record(input(), allow());

    const s2 = new JsonlAuditSink(path);
    const ev = s2.record(input(), allow());
    expect(ev.seq).toBe(2);
  });

  it("keeps independent chains per agent/session", () => {
    const path = join(dir, "audit.jsonl");
    const sink = new JsonlAuditSink(path);
    const pi = (agent: string, session: string): PolicyInput => ({
      agent: { id: agent },
      tool: { name: "http.get", arguments: { url: "https://x" } },
      session: { id: session },
    });
    const a0 = sink.record(pi("agent-A", "s1"), allow());
    const b0 = sink.record(pi("agent-B", "s2"), allow());
    const a1 = sink.record(pi("agent-A", "s1"), allow());
    const b1 = sink.record(pi("agent-B", "s2"), allow());

    expect([a0.seq, a1.seq]).toEqual([0, 1]);
    expect([b0.seq, b1.seq]).toEqual([0, 1]); // restarts at 0 per chain
    expect(a0.prev_hash).toBe(GENESIS_HASH);
    expect(b0.prev_hash).toBe(GENESIS_HASH);
    expect(a1.prev_hash).toBe(a0.hash);
    expect(b1.prev_hash).toBe(b0.hash);
    expect(verifyChain(path)).toBe(4);
  });

  it("verifyChain accepts a well-formed chain", () => {
    const sink = new JsonlAuditSink(join(dir, "audit.jsonl"));
    for (let i = 0; i < 5; i++) sink.record(input(), allow());
    expect(verifyChain(sink.path)).toBe(5);
  });

  it("verifyChain detects tampered prev_hash", () => {
    const path = join(dir, "audit.jsonl");
    const sink = new JsonlAuditSink(path);
    sink.record(input(), allow());
    sink.record(input(), allow());

    const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
    const e1 = JSON.parse(lines[1]!);
    e1.prev_hash = "f".repeat(64);
    lines[1] = JSON.stringify(e1);
    writeFileSync(path, lines.join("\n") + "\n");

    expect(() => verifyChain(path)).toThrowError(/prev_hash mismatch/);
  });

  it("verifyChain detects tampered body", () => {
    const path = join(dir, "audit.jsonl");
    const sink = new JsonlAuditSink(path);
    sink.record(input(), allow());

    const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
    const e0 = JSON.parse(lines[0]!);
    e0.reason = "tampered";
    lines[0] = JSON.stringify(e0);
    writeFileSync(path, lines.join("\n") + "\n");

    expect(() => verifyChain(path)).toThrowError(/hash mismatch/);
  });

  it("verifyChain returns 0 for missing file", () => {
    expect(verifyChain(join(dir, "nope.jsonl"))).toBe(0);
  });

  it("scanTail raises AuditError on corrupt last line", () => {
    const path = join(dir, "audit.jsonl");
    writeFileSync(path, "{not json}\n");
    expect(() => new JsonlAuditSink(path)).toThrowError(AuditError);
  });
});
