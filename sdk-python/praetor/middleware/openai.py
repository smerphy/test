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

from praetor_engine.types import Decision

from praetor.client import PraetorClient

_DENY_PAYLOAD = {"__praetor_blocked__": True}


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


def _parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def gate_tool_calls(
    tool_calls: Iterable[Any],
    *,
    client: PraetorClient,
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
        if not isinstance(tool_name, str):
            gated.append(call)
            continue
        arguments = _parse_arguments(_get(fn, "arguments"))
        tool_use_id = _get(call, "id")

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
