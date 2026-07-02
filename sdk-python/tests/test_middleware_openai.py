from __future__ import annotations

import json

from praetor_engine.evaluator import Policy
from praetor_engine.predicates import AlwaysPredicate, EqPredicate
from praetor_engine.types import Decision

from praetor.client import PraetorClient
from praetor.middleware.openai import gate_tool_calls


def _client(*policies: Policy) -> PraetorClient:
    return PraetorClient(policies=list(policies), default_agent_id="agent-1")


def _tc(name: str, args: dict, cid: str = "call_1") -> dict:
    return {
        "id": cid,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


class TestGateToolCalls:
    def test_allow_passes_through(self) -> None:
        call = _tc("http.get", {"url": "https://x"})
        out = gate_tool_calls(
            [call],
            client=_client(
                Policy(
                    id="allow",
                    effect=Decision.ALLOW,
                    when=EqPredicate(path="tool.name", value="http.get"),
                    reason="r",
                )
            ),
            session_id="s",
        )
        assert out == [call]

    def test_transform_re_serializes_arguments(self) -> None:
        call = _tc("http.get", {"url": "https://x", "method": "GET"})
        out = gate_tool_calls(
            [call],
            client=_client(
                Policy(
                    id="redact",
                    effect=Decision.TRANSFORM,
                    when=AlwaysPredicate(),
                    reason="r",
                    transform={"url": "<redacted>"},
                )
            ),
            session_id="s",
        )
        decoded = json.loads(out[0]["function"]["arguments"])
        assert decoded == {"url": "<redacted>", "method": "GET"}

    def test_deny_substitutes_blocked_payload(self) -> None:
        call = _tc("http.get", {"url": "https://x"})
        out = gate_tool_calls(
            [call],
            client=_client(
                Policy(
                    id="deny",
                    effect=Decision.DENY,
                    when=AlwaysPredicate(),
                    reason="blocked",
                )
            ),
            session_id="s",
        )
        decoded = json.loads(out[0]["function"]["arguments"])
        assert decoded["__praetor_blocked__"] is True
        assert decoded["policy_id"] == "deny"

    def test_malformed_json_arguments_treated_as_empty(self) -> None:
        # OpenAI sometimes streams incomplete JSON; we should not crash.
        call = {
            "id": "x",
            "type": "function",
            "function": {"name": "http.get", "arguments": "{not json"},
        }
        out = gate_tool_calls(
            [call],
            client=_client(
                Policy(
                    id="allow",
                    effect=Decision.ALLOW,
                    when=AlwaysPredicate(),
                    reason="r",
                )
            ),
            session_id="s",
        )
        # Allow path: pass through unchanged.
        assert out[0] == call

    def test_missing_function_block_passes_through(self) -> None:
        call = {"id": "x", "type": "function"}
        out = gate_tool_calls([call], client=_client(), session_id="s")
        assert out == [call]
