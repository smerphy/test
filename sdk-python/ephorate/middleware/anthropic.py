"""Anthropic Messages API middleware.

`gate_response(client, response, session_id)` walks the `tool_use`
content blocks of a Messages response and evaluates each through
Ephorate. The returned object mirrors the input but with:

  - DENY: the offending tool_use block is replaced with a tool_result-
    style sentinel so the model sees the rejection and can re-plan.
  - TRANSFORM: the block's `input` is replaced with the suggested
    transform.
  - REQUIRE_APPROVAL: handled by `EphorateClient.evaluate` (blocks on the
    approval handler before returning).

Provider-shape coupling is intentionally narrow: we only touch the
fields we need (`type`, `id`, `name`, `input`), so this works for both
the official `anthropic` SDK's typed objects and raw dicts from
non-Python callers.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ephorate_engine.types import Decision

from ephorate.client import EphorateClient

# Sentinel input we substitute when a tool_use is denied so the model
# can see what happened and recover (rather than us silently dropping
# the block, which leaves the conversation in an undefined state).
_DENY_INPUT_TEMPLATE = {
    "__ephorate_blocked__": True,
}


def _is_tool_use_block(block: Any) -> bool:
    return bool(_get(block, "type") == "tool_use")


def _get(block: Any, attr: str, default: Any = None) -> Any:
    if isinstance(block, dict):
        return block.get(attr, default)
    return getattr(block, attr, default)


def _set_input(block: Any, new_input: dict[str, Any]) -> Any:
    if isinstance(block, dict):
        return {**block, "input": new_input}
    # Pydantic-style typed object: reconstruct via model_copy when available.
    model_copy = getattr(block, "model_copy", None)
    if callable(model_copy):
        return model_copy(update={"input": new_input})
    raise TypeError(
        f"don't know how to update tool_use block of type {type(block).__name__}"
    )


def gate_tool_use_blocks(
    blocks: Iterable[Any],
    *,
    client: EphorateClient,
    session_id: str,
    agent_id: str | None = None,
    agent_name: str | None = None,
    agent_version: str | None = None,
    context: dict[str, Any] | None = None,
) -> list[Any]:
    """Evaluate every tool_use block and return a new list with applied effects.

    Non-tool_use blocks pass through unchanged.
    """
    gated: list[Any] = []
    for block in blocks:
        if not _is_tool_use_block(block):
            gated.append(block)
            continue

        tool_name = _get(block, "name")
        tool_input = _get(block, "input", {})
        tool_use_id = _get(block, "id")

        # Fail closed: if we cannot identify the tool or reliably read the
        # exact arguments that will execute, deny rather than passing the
        # call through unevaluated. Evaluating a coerced `{}` and then
        # emitting the original block would let a malformed or adversarial
        # response bypass Ephorate entirely.
        if not isinstance(tool_name, str) or not isinstance(tool_input, dict):
            gated.append(
                _set_input(
                    block,
                    {
                        **_DENY_INPUT_TEMPLATE,
                        "policy_id": None,
                        "reason": (
                            "unevaluatable tool_use block "
                            "(missing/invalid name or input)"
                        ),
                        "decision": Decision.DENY.value,
                    },
                )
            )
            continue

        result = client.evaluate(
            tool_name=tool_name,
            tool_arguments=tool_input,
            session_id=session_id,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_version=agent_version,
            tool_use_id=tool_use_id,
            context=context,
        )

        if result.decision is Decision.ALLOW:
            gated.append(block)
        elif result.decision is Decision.TRANSFORM:
            assert result.suggested_transform is not None
            merged = {**tool_input, **result.suggested_transform}
            gated.append(_set_input(block, merged))
        else:  # DENY (approval-denied or explicit) — substitute the sentinel
            gated.append(
                _set_input(
                    block,
                    {
                        **_DENY_INPUT_TEMPLATE,
                        "policy_id": result.matched_policy_id,
                        "reason": result.reason,
                        "decision": result.decision.value,
                    },
                )
            )

    return gated


def gate_response(
    response: Any,
    *,
    client: EphorateClient,
    session_id: str,
    **kwargs: Any,
) -> Any:
    """Convenience: gate the `content` of an Anthropic Messages response in place-of.

    Returns a new response-shaped object (dict or model_copy of the original).
    """
    content = _get(response, "content", [])
    gated = gate_tool_use_blocks(
        content, client=client, session_id=session_id, **kwargs
    )

    if isinstance(response, dict):
        return {**response, "content": gated}
    model_copy = getattr(response, "model_copy", None)
    if callable(model_copy):
        return model_copy(update={"content": gated})
    raise TypeError(
        f"don't know how to update response of type {type(response).__name__}"
    )


__all__ = ["gate_response", "gate_tool_use_blocks"]
