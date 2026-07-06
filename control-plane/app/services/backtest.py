"""Policy backtesting: replay historical audit events through a candidate
policy bundle and diff the decisions.

Answers "what would this policy have done?" before rollout. For each stored
audit event in the window we rebuild its ``PolicyInput`` and evaluate it against
the candidate bundle, then compare the new decision to the one that was actually
recorded. The report surfaces how many calls the candidate would tighten vs.
loosen, the full old→new transition matrix, and concrete examples of the
changed decisions — so an author sees the blast radius before shipping.

Read-only: it never writes findings or mutates events; it just re-evaluates.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from praetor_engine.evaluator import Evaluator
from praetor_engine.parser import parse_bundle
from praetor_engine.types import AgentInfo, PolicyInput, SessionInfo, ToolCall
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent

# Restrictiveness rank — a higher-ranked decision is more restrictive, so a
# transition to a higher rank "tightens" and to a lower rank "loosens".
_RANK = {"allow": 0, "transform": 1, "require_approval": 2, "deny": 3}

_MAX_EXAMPLES = 50


def backtest_policy(
    session: Session,
    org_id: str,
    *,
    yaml_text: str,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 10_000,
) -> dict[str, Any]:
    """Evaluate a candidate bundle over recorded audit events. Raises
    ``PolicyParseError`` on an invalid bundle (surfaced as 422 by the router)."""
    evaluator = Evaluator(policies=parse_bundle(yaml_text))

    stmt = select(AuditEvent).where(AuditEvent.organization_id == org_id)
    if since is not None:
        stmt = stmt.where(AuditEvent.timestamp >= since)
    if until is not None:
        stmt = stmt.where(AuditEvent.timestamp < until)
    stmt = stmt.order_by(AuditEvent.timestamp.desc()).limit(limit)

    evaluated = 0
    unchanged = 0
    newly_denied = newly_allowed = 0
    more_restrictive = less_restrictive = 0
    transitions: dict[str, int] = {}
    examples: list[dict[str, Any]] = []

    for ev in session.execute(stmt).scalars():
        evaluated += 1
        result = evaluator.evaluate(
            PolicyInput(
                agent=AgentInfo(id=ev.agent_id),
                tool=ToolCall(name=ev.tool_name, arguments=ev.tool_arguments),
                session=SessionInfo(id=ev.session_id),
                context=ev.context or {},
            )
        )
        old = ev.decision
        new = result.decision.value
        if old == new:
            unchanged += 1
            continue

        transitions[f"{old}->{new}"] = transitions.get(f"{old}->{new}", 0) + 1
        if new == "deny":
            newly_denied += 1
        if new == "allow":
            newly_allowed += 1
        old_rank, new_rank = _RANK.get(old, 0), _RANK.get(new, 0)
        if new_rank > old_rank:
            more_restrictive += 1
        elif new_rank < old_rank:
            less_restrictive += 1

        if len(examples) < _MAX_EXAMPLES:
            examples.append(
                {
                    "event_id": ev.id,
                    "timestamp": ev.timestamp.isoformat(),
                    "agent_id": ev.agent_id,
                    "tool_name": ev.tool_name,
                    "old_decision": old,
                    "new_decision": new,
                    "new_reason": result.reason,
                    "new_policy_id": result.matched_policy_id,
                }
            )

    return {
        "evaluated": evaluated,
        "since": since.isoformat() if since else None,
        "until": until.isoformat() if until else None,
        "summary": {
            "unchanged": unchanged,
            "changed": evaluated - unchanged,
            "newly_denied": newly_denied,
            "newly_allowed": newly_allowed,
            "more_restrictive": more_restrictive,
            "less_restrictive": less_restrictive,
        },
        "transitions": transitions,
        "examples": examples,
    }


__all__ = ["backtest_policy"]
