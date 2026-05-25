/**
 * Tamper-evident audit log (TS port).
 *
 * Same on-disk format as the Python SDK so events can be ingested by
 * the same control-plane endpoint. SHA-256 Merkle chain over the
 * canonicalized event body.
 */

import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { AuditError } from "./errors.js";
import type { Decision, DecisionResult, PolicyInput } from "./types.js";

export const GENESIS_HASH = "0".repeat(64);

export interface AuditEvent {
  seq: number;
  timestamp: string; // ISO-8601 with offset
  agent_id: string;
  session_id: string;
  tool_name: string;
  tool_arguments: Record<string, unknown>;
  tool_use_id: string | null;
  decision: Decision;
  reason: string;
  matched_policy_id: string | null;
  suggested_transform: Record<string, unknown> | null;
  context: Record<string, unknown>;
  evaluator_version: string;
  prev_hash: string;
  hash: string;
}

export interface AuditSink {
  record(input: PolicyInput, decision: DecisionResult): AuditEvent;
}

/**
 * Canonicalize a JSON value with sorted object keys. Matches the
 * Python `json.dumps(..., sort_keys=True, separators=(",",":"))`
 * byte-for-byte so cross-language chain verification works.
 */
function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]))
      .join(",") +
    "}"
  );
}

function sha256Hex(bytes: string): string {
  return createHash("sha256").update(bytes, "utf8").digest("hex");
}

function computeHash(eventMinusHash: Omit<AuditEvent, "hash">): string {
  return sha256Hex(canonicalize(eventMinusHash));
}

const EVALUATOR_VERSION = "0.1.0";

function buildEvent(args: {
  seq: number;
  prevHash: string;
  input: PolicyInput;
  decision: DecisionResult;
  now?: Date;
}): AuditEvent {
  const ts = (args.now ?? new Date()).toISOString();
  const body: Omit<AuditEvent, "hash"> = {
    seq: args.seq,
    timestamp: ts,
    agent_id: args.input.agent.id,
    session_id: args.input.session.id,
    tool_name: args.input.tool.name,
    tool_arguments: args.input.tool.arguments,
    tool_use_id: args.input.tool.tool_use_id ?? null,
    decision: args.decision.decision,
    reason: args.decision.reason,
    matched_policy_id: args.decision.matched_policy_id ?? null,
    suggested_transform: args.decision.suggested_transform ?? null,
    context: args.input.context ?? {},
    evaluator_version: EVALUATOR_VERSION,
    prev_hash: args.prevHash,
  };
  return { ...body, hash: computeHash(body) };
}

export class NullAuditSink implements AuditSink {
  record(input: PolicyInput, decision: DecisionResult): AuditEvent {
    return buildEvent({ seq: 0, prevHash: GENESIS_HASH, input, decision });
  }
}

export class JsonlAuditSink implements AuditSink {
  private seq: number;
  private prevHash: string;

  constructor(public readonly path: string) {
    const [seq, prevHash] = this.scanTail();
    this.seq = seq;
    this.prevHash = prevHash;
  }

  get currentSeq(): number {
    return this.seq;
  }

  private scanTail(): [number, string] {
    if (!existsSync(this.path)) return [-1, GENESIS_HASH];
    const content = readFileSync(this.path, "utf8");
    const lines = content.split("\n").filter((l) => l.length > 0);
    if (lines.length === 0) return [-1, GENESIS_HASH];
    const last = lines[lines.length - 1]!;
    try {
      const event = JSON.parse(last) as AuditEvent;
      return [event.seq, event.hash];
    } catch (err) {
      throw new AuditError(`corrupt audit log tail: ${(err as Error).message}`);
    }
  }

  record(input: PolicyInput, decision: DecisionResult): AuditEvent {
    const nextSeq = this.seq + 1;
    const event = buildEvent({
      seq: nextSeq,
      prevHash: this.prevHash,
      input,
      decision,
    });
    mkdirSync(dirname(this.path), { recursive: true });
    // Node's appendFileSync does not call fsync; for production-grade
    // durability use fs.openSync + fs.writeSync + fs.fsyncSync. Keep
    // appendFileSync here for simplicity; the Python SDK is the
    // canonical reference for fsync-on-record behavior.
    appendFileSync(this.path, JSON.stringify(event) + "\n", { mode: 0o600 });
    this.seq = nextSeq;
    this.prevHash = event.hash;
    return event;
  }
}

/** Walk the chain and throw on the first broken link or hash mismatch. */
export function verifyChain(path: string): number {
  if (!existsSync(path)) return 0;
  const lines = readFileSync(path, "utf8").split("\n");
  let expectedPrev = GENESIS_HASH;
  let count = 0;
  let lineNo = 0;
  for (const raw of lines) {
    lineNo += 1;
    const stripped = raw.trim();
    if (stripped.length === 0) continue;
    let event: AuditEvent;
    try {
      event = JSON.parse(stripped) as AuditEvent;
    } catch (err) {
      throw new AuditError(
        `line ${lineNo}: invalid JSON: ${(err as Error).message}`,
      );
    }
    if (event.prev_hash !== expectedPrev) {
      throw new AuditError(
        `line ${lineNo}: prev_hash mismatch (expected ${expectedPrev}, got ${event.prev_hash})`,
      );
    }
    const { hash, ...body } = event;
    const recomputed = computeHash(body);
    if (recomputed !== hash) {
      throw new AuditError(
        `line ${lineNo}: hash mismatch (recomputed ${recomputed}, stored ${hash})`,
      );
    }
    expectedPrev = hash;
    count += 1;
  }
  return count;
}
