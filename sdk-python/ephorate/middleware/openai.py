"""OpenAI Chat Completions middleware.

OpenAI's `tool_calls` shape:

    choices[i].message.tool_calls[k] = {
        "id": "...",
        "type": "function",
        "function": {"name": "...", "arguments": "<json string>"}
    }

Arguments come back as a JSON string, not a dict. We parse, evaluate,
and re-serialize. DENY substitutes a sentinel `arguments` payload (still
valid JSON) so the model can see what happened on the next turn.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from ephorate_engine.types import Decision

from ephorate.client import EphorateClient

_DENY_PAYLOAD = {"__ephorate_blocked__": True}


def _get(obj: Any, attr: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def _set(obj: Any, attr: str, value: Any) -> Any:
    if isinstance(obj, dict):
        return {**obj, attr: value}
    model_copy = getattr(obj, "model_copy", None)
    if callable(model_copy):
        return model_copy(update={attr: value})
    raise TypeError(f"cannot update field {attr!r} on {type(obj).__name__}")


def _parse_arguments(raw: Any) -> dict[str, Any] | None:
    """Parse tool-call arguments into a dict.

    Returns `None` when arguments are *present but not a JSON object*
    (malformed JSON, or a non-object like a list/scalar). The caller must
    treat `None` as fail-closed: we cannot evaluate the policy against the
    exact arguments that will execute, so the call is denied rather than
    evaluated as an empty `{}` and passed through unchanged.

    Absent/empty arguments legitimately mean "no arguments" and parse to `{}`.
    """
    if isinstance(raw, dict):
        return raw
    if raw is None or raw == "":
        return {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def gate_tool_calls(
    tool_calls: Iterable[Any],
    *,
    client: EphorateClient,
    session_id: str,
    agent_id: str | None = None,
    agent_name: str | None = None,
    agent_version: str | None = None,
    context: dict[str, Any] | None = None,
) -> list[Any]:
    gated: list[Any] = []
    for call in tool_calls:
        fn = _get(call, "function")
        if fn is None:
            gated.append(call)
            continue
        tool_name = _get(fn, "name")
        arguments = _parse_arguments(_get(fn, "arguments"))
        tool_use_id = _get(call, "id")

        # Fail closed: an unidentifiable tool name, or arguments we cannot
        # parse into the exact object that will execute, must be denied — not
        # passed through. Evaluating a coerced `{}` and then emitting the
        # original call would bypass argument-keyed deny policies.
        if not isinstance(tool_name, str) or arguments is None:
            payload = {
                **_DENY_PAYLOAD,
                "policy_id": None,
                "reason": "unevaluatable tool call (invalid name or arguments)",
                "decision": Decision.DENY.value,
            }
            gated.append(_set(call, "function", _set(fn, "arguments", json.dumps(payload))))
            continue

        result = client.evaluate(
            tool_name=tool_name,
            tool_arguments=arguments,
            session_id=session_id,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_version=agent_version,
            tool_use_id=tool_use_id,
            context=context,
        )

        if result.decision is Decision.ALLOW:
            gated.append(call)
            continue

        if result.decision is Decision.TRANSFORM:
            assert result.suggested_transform is not None
            merged = {**arguments, **result.suggested_transform}
            new_fn = _set(fn, "arguments", json.dumps(merged))
        else:
            payload = {
                **_DENY_PAYLOAD,
                "policy_id": result.matched_policy_id,
                "reason": result.reason,
                "decision": result.decision.value,
            }
            new_fn = _set(fn, "arguments", json.dumps(payload))

        gated.append(_set(call, "function", new_fn))

    return gated


__all__ = ["gate_tool_calls"]
