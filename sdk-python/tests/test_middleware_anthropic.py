from __future__ import annotations

from praetor_engine.evaluator import Policy
from praetor_engine.predicates import AlwaysPredicate, EqPredicate
from praetor_engine.types import Decision

from praetor.client import PraetorClient
from praetor.middleware.anthropic import (
    gate_response,
    gate_tool_use_blocks,
)


def _client(*policies: Policy) -> PraetorClient:
    return PraetorClient(policies=list(policies), default_agent_id="agent-1")


def _tu(name: str, args: dict, bid: str = "toolu_1") -> dict:
    return {"type": "tool_use", "id": bid, "name": name, "input": args}


class TestGateBlocks:
    def test_text_blocks_pass_through(self) -> None:
        blocks = [{"type": "text", "text": "hello"}]
        out = gate_tool_use_blocks(
            blocks,
            client=_client(
                Policy(
                    id="p",
                    effect=Decision.ALLOW,
                    when=AlwaysPredicate(),
                    reason="r",
                )
            ),
            session_id="s",
        )
        assert out == blocks

    def test_allow_passes_block_unchanged(self) -> None:
        block = _tu("http.get", {"url": "https://x"})
        out = gate_tool_use_blocks(
            [block],
            client=_client(
                Policy(
                    id="p",
                    effect=Decision.ALLOW,
                    when=EqPredicate(path="tool.name", value="http.get"),
                    reason="r",
                )
            ),
            session_id="s",
        )
        assert out == [block]

    def test_deny_replaces_input_with_sentinel(self) -> None:
        block = _tu("http.get", {"url": "https://x"})
        out = gate_tool_use_blocks(
            [block],
            client=_client(
                Policy(
                    id="deny-http",
                    effect=Decision.DENY,
                    when=EqPredicate(path="tool.name", value="http.get"),
                    reason="blocked",
                )
            ),
            session_id="s",
        )
        assert out[0]["input"]["__praetor_blocked__"] is True
        assert out[0]["input"]["policy_id"] == "deny-http"
        assert out[0]["input"]["decision"] == "deny"
        # Tool name + id preserved so the model can correlate.
        assert out[0]["name"] == "http.get"
        assert out[0]["id"] == "toolu_1"

    def test_transform_merges_into_input(self) -> None:
        block = _tu("http.get", {"url": "https://x.com/path", "method": "GET"})
        out = gate_tool_use_blocks(
            [block],
            client=_client(
                Policy(
                    id="redact",
                    effect=Decision.TRANSFORM,
                    when=AlwaysPredicate(),
                    reason="redact url",
                    transform={"url": "<redacted>"},
                )
            ),
            session_id="s",
        )
        assert out[0]["input"] == {"url": "<redacted>", "method": "GET"}

    def test_default_deny_when_no_policy_matches(self) -> None:
        block = _tu("http.get", {"url": "https://x"})
        out = gate_tool_use_blocks(
            [block],
            client=_client(),  # empty bundle
            session_id="s",
        )
        assert out[0]["input"]["__praetor_blocked__"] is True
        assert out[0]["input"]["policy_id"] is None

    def test_malformed_blocks_pass_through(self) -> None:
        # tool_use missing name
        block = {"type": "tool_use", "id": "x"}
        out = gate_tool_use_blocks([block], client=_client(), session_id="s")
        assert out == [block]


class TestPydanticLikeBlocks:
    """Verify we update typed objects (Pydantic-shaped) via model_copy."""

    def test_model_copy_path(self) -> None:
        from pydantic import BaseModel

        class ToolUse(BaseModel):
            type: str = "tool_use"
            id: str
            name: str
            input: dict

        block = ToolUse(id="toolu_1", name="http.get", input={"url": "https://x"})
        out = gate_tool_use_blocks(
            [block],
            client=_client(
                Policy(
                    id="deny",
                    effect=Decision.DENY,
                    when=AlwaysPredicate(),
                    reason="r",
                )
            ),
            session_id="s",
        )
        gated = out[0]
        assert isinstance(gated, ToolUse)
        assert gated.input["__praetor_blocked__"] is True


class TestGateResponse:
    def test_round_trip_through_dict_response(self) -> None:
        response = {
            "id": "msg_1",
            "content": [
                {"type": "text", "text": "I'll fetch that for you."},
                _tu("http.get", {"url": "https://x"}),
            ],
        }
        out = gate_response(
            response,
            client=_client(
                Policy(
                    id="deny-http",
                    effect=Decision.DENY,
                    when=AlwaysPredicate(),
                    reason="blocked",
                )
            ),
            session_id="s",
        )
        assert out["id"] == "msg_1"
        assert out["content"][0] == {
            "type": "text",
            "text": "I'll fetch that for you.",
        }
        assert out["content"][1]["input"]["__praetor_blocked__"] is True
