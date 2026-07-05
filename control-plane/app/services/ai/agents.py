"""Multi-agent reasoning over a vendor-neutral LLM provider.

Two capabilities:

1. **assess_action** — a 3-agent panel (Risk Assessor → adversarial Safety
   Reviewer → Adjudicator) recommends allow / deny / require_approval for a
   tool call, with confidence and rationale.
2. **propose_rules** — a Rule Author drafts candidate detection rules from
   recent risk patterns and an adversarial Reviewer prunes over-broad ones.

Safety invariants:

* The AI is **advisory by default**. `reconcile()` guarantees the AI can only
  ever make a decision *more* restrictive than the deterministic engine —
  never loosen a deny/approval into an allow. So a hallucinating or
  compromised model cannot weaken policy.
* Any provider/parse failure degrades to ``abstain`` (deterministic decision
  stands), never to an unsafe allow.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.services.ai.providers import LLMError, LLMProvider

DECISIONS = {"allow", "deny", "require_approval", "abstain"}
_RANK = {"allow": 0, "require_approval": 1, "deny": 2}

_JSON_OBJ = re.compile(r"\{.*\}", re.DOTALL)
_JSON_ARR = re.compile(r"\[.*\]", re.DOTALL)


def _parse_json(text: str, array: bool = False) -> Any:
    """Best-effort JSON extraction from a model response."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass
    pattern = _JSON_ARR if array else _JSON_OBJ
    match = pattern.search(text or "")
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


# ---------------------------------------------------------------------------
# Action assessment
# ---------------------------------------------------------------------------
@dataclass
class ActionContext:
    tool_name: str
    tool_arguments: dict[str, Any]
    agent_id: str | None = None
    session_id: str | None = None
    deterministic_decision: str = "require_approval"
    reason: str = ""
    matched_policy_id: str | None = None


@dataclass
class AgentOpinion:
    role: str
    decision: str
    confidence: float
    rationale: str


@dataclass
class Assessment:
    decision: str
    confidence: float
    rationale: str
    opinions: list[AgentOpinion] = field(default_factory=list)
    error: str | None = None


_RISK_SYSTEM = (
    "You are a security risk assessor for an AI-agent action firewall. Given a "
    "tool call an autonomous agent wants to make, judge how dangerous it is "
    "(data exfiltration, destructive action, privilege escalation, prompt "
    "injection payload, policy evasion). Respond with ONLY a JSON object: "
    '{"decision": "allow|deny|require_approval", "confidence": 0.0-1.0, '
    '"rationale": "one sentence"}. Prefer require_approval when uncertain.'
)
_REVIEW_SYSTEM = (
    "You are an adversarial safety reviewer. You are given a proposed decision "
    "about an AI agent's tool call. Argue the opposite: if it was allowed, why "
    "might it be dangerous; if blocked, why might it be a false positive. Then "
    "give your own independent judgement as ONLY a JSON object: "
    '{"decision": "allow|deny|require_approval", "confidence": 0.0-1.0, '
    '"rationale": "one sentence"}.'
)
_ADJUDICATE_SYSTEM = (
    "You are the adjudicator. Given a tool call and two independent security "
    "opinions, decide the final recommendation, weighting caution. Respond with "
    'ONLY a JSON object: {"decision": "allow|deny|require_approval", '
    '"confidence": 0.0-1.0, "rationale": "one sentence"}.'
)


def _action_brief(ctx: ActionContext) -> str:
    args = json.dumps(ctx.tool_arguments, ensure_ascii=False, default=str)[:4000]
    return (
        f"tool_name: {ctx.tool_name}\n"
        f"arguments: {args}\n"
        f"agent_id: {ctx.agent_id}\n"
        f"deterministic_engine_decision: {ctx.deterministic_decision}\n"
        f"engine_reason: {ctx.reason}\n"
        f"matched_policy: {ctx.matched_policy_id}"
    )


def _opinion(provider: LLMProvider, role: str, system: str, user: str) -> AgentOpinion:
    raw = provider.complete(system=system, user=user)
    data = _parse_json(raw)
    if not isinstance(data, dict):
        return AgentOpinion(role, "abstain", 0.0, "unparseable model response")
    decision = str(data.get("decision", "abstain")).lower()
    if decision not in DECISIONS:
        decision = "abstain"
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
    except (TypeError, ValueError):
        confidence = 0.0
    rationale = str(data.get("rationale", ""))[:1000]
    return AgentOpinion(role, decision, confidence, rationale)


def assess_action(provider: LLMProvider, ctx: ActionContext) -> Assessment:
    """Run the 3-agent panel. Degrades to abstain on any provider error."""
    brief = _action_brief(ctx)
    try:
        risk = _opinion(provider, "risk_assessor", _RISK_SYSTEM, brief)
        review_user = (
            f"{brief}\n\nProposed decision from the risk assessor: "
            f"{risk.decision} ({risk.rationale})"
        )
        review = _opinion(provider, "safety_reviewer", _REVIEW_SYSTEM, review_user)
        adj_user = (
            f"{brief}\n\nOpinion A (risk_assessor): {risk.decision} "
            f"conf={risk.confidence} — {risk.rationale}\n"
            f"Opinion B (safety_reviewer): {review.decision} "
            f"conf={review.confidence} — {review.rationale}"
        )
        final = _opinion(provider, "adjudicator", _ADJUDICATE_SYSTEM, adj_user)
    except LLMError as exc:
        return Assessment(
            decision="abstain",
            confidence=0.0,
            rationale="AI provider error; deterministic decision stands",
            error=str(exc),
        )
    return Assessment(
        decision=final.decision,
        confidence=final.confidence,
        rationale=final.rationale,
        opinions=[risk, review, final],
    )


def reconcile(deterministic: str, ai_decision: str, *, mode: str) -> str:
    """Combine the engine decision with the AI recommendation.

    * ``advisory`` — engine decision is authoritative; AI is annotation only.
    * ``enforce``  — the AI may only *tighten*: the final decision is the more
      restrictive of the two (deny > require_approval > allow). An AI
      ``allow``/``abstain`` never loosens the engine's decision.
    """
    if mode != "enforce":
        return deterministic
    det_rank = _RANK.get(deterministic, 1)
    ai_rank = _RANK.get(ai_decision, 0) if ai_decision in ("deny", "require_approval") else 0
    return next(k for k, v in _RANK.items() if v == max(det_rank, ai_rank))


# ---------------------------------------------------------------------------
# Rule improvement
# ---------------------------------------------------------------------------
@dataclass
class RuleDraft:
    title: str
    rationale: str
    severity: str
    category: str
    spec: dict[str, Any]
    confidence: float = 0.5
    atlas_technique: str | None = None
    owasp_llm: str | None = None


_AUTHOR_SYSTEM = (
    "You are a detection engineer for an AI-agent security platform. Given a "
    "summary of recent security findings and denied tool calls, propose up to 3 "
    "NEW detection rules that would catch the recurring risky patterns. Each "
    "rule's spec is a bounded structured match (no code/regex) with these "
    "optional fields: decision (allow|deny|require_approval|transform), "
    "matched_policy_prefix, matched_policy_contains, tool_name, "
    "group_by (agent|session), threshold (int), window_minutes (int). At least "
    "one of decision/matched_policy_prefix/matched_policy_contains/tool_name "
    "must be set. Respond with ONLY a JSON array of objects: "
    '{"title","rationale","severity":"info|low|medium|high|critical",'
    '"category":"prompt_injection|data_exfil|abuse|policy_violation|'
    'approval_abuse|anomaly|threat_intel","spec":{...}}.'
)
_REVIEWER_SYSTEM = (
    "You are an adversarial detection reviewer. For each proposed rule, decide "
    "whether it is precise enough to avoid excessive false positives and is "
    "genuinely useful. Respond with ONLY a JSON array with one object per input "
    'rule in order: {"keep": true|false, "confidence": 0.0-1.0, '
    '"reason": "one sentence"}.'
)

_VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}
_VALID_CATEGORY = {
    "prompt_injection",
    "data_exfil",
    "abuse",
    "policy_violation",
    "approval_abuse",
    "anomaly",
    "threat_intel",
}
_SPEC_FIELDS = {
    "decision",
    "matched_policy_prefix",
    "matched_policy_contains",
    "tool_name",
    "group_by",
    "threshold",
    "window_minutes",
}
_SPEC_CONDITIONS = {
    "decision",
    "matched_policy_prefix",
    "matched_policy_contains",
    "tool_name",
}


def _sanitize_spec(spec: Any) -> dict[str, Any] | None:
    if not isinstance(spec, dict):
        return None
    clean = {k: v for k, v in spec.items() if k in _SPEC_FIELDS and v not in (None, "")}
    if not any(k in clean for k in _SPEC_CONDITIONS):
        return None
    if "group_by" in clean and clean["group_by"] not in ("agent", "session"):
        clean.pop("group_by")
    for numeric in ("threshold", "window_minutes"):
        if numeric in clean:
            try:
                clean[numeric] = int(clean[numeric])
            except (TypeError, ValueError):
                clean.pop(numeric)
    return clean


def propose_rules(
    provider: LLMProvider, *, pattern_summary: str, max_rules: int = 3
) -> list[RuleDraft]:
    """Author + review candidate detection rules. Returns validated drafts."""
    try:
        authored = _parse_json(
            provider.complete(system=_AUTHOR_SYSTEM, user=pattern_summary),
            array=True,
        )
    except LLMError:
        return []
    if not isinstance(authored, list):
        return []

    candidates: list[RuleDraft] = []
    for item in authored[:max_rules]:
        if not isinstance(item, dict):
            continue
        spec = _sanitize_spec(item.get("spec"))
        if spec is None:
            continue
        severity = str(item.get("severity", "medium")).lower()
        category = str(item.get("category", "anomaly")).lower()
        if severity not in _VALID_SEVERITY or category not in _VALID_CATEGORY:
            continue
        title = str(item.get("title", "")).strip()[:200]
        if not title:
            continue
        candidates.append(
            RuleDraft(
                title=title,
                rationale=str(item.get("rationale", ""))[:2000],
                severity=severity,
                category=category,
                spec=spec,
            )
        )
    if not candidates:
        return []

    # Adversarial review pass.
    review_user = json.dumps(
        [{"title": c.title, "spec": c.spec} for c in candidates]
    )
    try:
        verdicts = _parse_json(
            provider.complete(system=_REVIEWER_SYSTEM, user=review_user), array=True
        )
    except LLMError:
        verdicts = None

    kept: list[RuleDraft] = []
    for i, cand in enumerate(candidates):
        verdict = verdicts[i] if isinstance(verdicts, list) and i < len(verdicts) else None
        if isinstance(verdict, dict):
            if not verdict.get("keep", True):
                continue
            try:
                cand.confidence = max(0.0, min(1.0, float(verdict.get("confidence", 0.5))))
            except (TypeError, ValueError):
                cand.confidence = 0.5
        kept.append(cand)
    return kept


__all__ = [
    "ActionContext",
    "AgentOpinion",
    "Assessment",
    "RuleDraft",
    "assess_action",
    "propose_rules",
    "reconcile",
]
