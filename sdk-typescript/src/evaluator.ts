/**
 * Pure TypeScript port of the engine's evaluator.
 *
 * Same contract as `ephorate_engine.evaluator.Evaluator`:
 *   - side-effect-free
 *   - highest-precedence wins (deny > require_approval > transform > allow)
 *   - first-match within a tier
 *   - default deny when no policy matches
 */

import type { Decision, DecisionResult, Policy, PolicyInput, Predicate } from "./types.js";

const RANK: Record<Decision, number> = {
  allow: 0,
  transform: 1,
  require_approval: 2,
  deny: 3,
};

const MISSING = Symbol("MISSING");

function resolvePath(input: PolicyInput, path: string): unknown {
  let current: unknown = input;
  for (const part of path.split(".")) {
    if (current === null || current === undefined) return MISSING;
    if (typeof current !== "object") return MISSING;
    // Match Python's dict-only semantics: own keys only (not inherited
    // prototype members like `constructor`/`toString`), and arrays are not
    // traversable (Python lists are not dicts, so a path into one is MISSING).
    if (Array.isArray(current)) return MISSING;
    const obj = current as Record<string, unknown>;
    if (!Object.prototype.hasOwnProperty.call(obj, part)) return MISSING;
    current = obj[part];
  }
  return current;
}

const regexCache = new Map<string, RegExp>();
function compile(pattern: string): RegExp {
  let re = regexCache.get(pattern);
  if (re === undefined) {
    re = new RegExp(pattern);
    regexCache.set(pattern, re);
  }
  return re;
}

function evalPredicate(predicate: Predicate, input: PolicyInput): boolean {
  switch (predicate.op) {
    case "always":
      return true;
    case "eq": {
      const v = resolvePath(input, predicate.path);
      return v !== MISSING && v === predicate.value;
    }
    case "in": {
      const v = resolvePath(input, predicate.path);
      if (v === MISSING) return false;
      // Use Object.is for stable comparison with primitives.
      return predicate.values.some((candidate) => Object.is(v, candidate) || v === candidate);
    }
    case "matches": {
      const v = resolvePath(input, predicate.path);
      if (v === MISSING || typeof v !== "string") return false;
      return compile(predicate.pattern).test(v);
    }
    case "and":
      return predicate.clauses.every((c) => evalPredicate(c, input));
    case "or":
      return predicate.clauses.some((c) => evalPredicate(c, input));
    case "not":
      return !evalPredicate(predicate.clause, input);
  }
}

export class Evaluator {
  private readonly policies: readonly Policy[];

  constructor(policies: readonly Policy[]) {
    this.policies = [...policies];
  }

  evaluate(input: PolicyInput): DecisionResult {
    let winner: Policy | null = null;
    let winnerRank = -1;
    for (const policy of this.policies) {
      if (!evalPredicate(policy.when, input)) continue;
      const r = RANK[policy.effect];
      if (r > winnerRank) {
        winner = policy;
        winnerRank = r;
      }
    }
    if (winner === null) {
      return { decision: "deny", reason: "default deny: no policy matched", matched_policy_id: null };
    }
    return {
      decision: winner.effect,
      reason: winner.reason,
      matched_policy_id: winner.id,
      suggested_transform: winner.transform ?? null,
    };
  }
}
