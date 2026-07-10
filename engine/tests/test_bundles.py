from __future__ import annotations

import pytest

from ephorate_engine.bundles import (
    BUNDLES,
    bundle_path,
    list_bundles,
    load_bundle,
)


class TestListAndPath:
    def test_lists_all_shipped_bundles(self) -> None:
        names = list_bundles()
        assert set(names) == {
            "nist_ai_rmf",
            "iso_42001",
            "eu_ai_act",
            "agent_abuse_patterns",
            "prompt_injection",
        }
        # Sorted output for stable CLI display.
        assert names == sorted(names)

    def test_bundle_path_exists_for_every_registered_name(self) -> None:
        for name in BUNDLES:
            assert bundle_path(name).is_file()

    def test_unknown_bundle_raises_keyerror(self) -> None:
        with pytest.raises(KeyError, match="unknown bundle"):
            bundle_path("bogus")


class TestLoadBundle:
    @pytest.mark.parametrize("name", ["nist_ai_rmf", "iso_42001", "eu_ai_act"])
    def test_each_starter_bundle_parses(self, name: str) -> None:
        policies = load_bundle(name)
        assert len(policies) >= 3
        # Every policy is tagged with the framework key via metadata.
        for p in policies:
            assert name in p.metadata, (
                f"policy {p.id} in {name} bundle missing metadata key"
            )

    def test_load_bundle_returns_unique_ids(self) -> None:
        for name in list_bundles():
            policies = load_bundle(name)
            ids = [p.id for p in policies]
            assert len(ids) == len(set(ids)), f"duplicate ids in {name}"


class TestEuAiActHumanOverride:
    """The Art. 14(4)(d) override deny must not fail open on string-encoded
    boolean flags (a tool serializing `force` as `"true"`)."""

    @pytest.mark.parametrize("force", [True, 1, "true", "TRUE", "yes", "1"])
    def test_human_override_flag_denied(self, force: object) -> None:
        from ephorate_engine.evaluator import Evaluator
        from ephorate_engine.types import (
            AgentInfo,
            Decision,
            PolicyInput,
            SessionInfo,
            ToolCall,
        )

        evaluator = Evaluator(policies=load_bundle("eu_ai_act"))
        result = evaluator.evaluate(
            PolicyInput(
                agent=AgentInfo(id="a"),
                tool=ToolCall(name="law_enforcement.search", arguments={"force": force}),
                session=SessionInfo(id="s"),
            )
        )
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "eu-ai-act-14-4d-block-human-override-flag"

    @pytest.mark.parametrize("force", [False, 0, "false", "no", ""])
    def test_non_override_values_not_denied_by_flag_rule(self, force: object) -> None:
        from ephorate_engine.evaluator import Evaluator
        from ephorate_engine.types import (
            AgentInfo,
            PolicyInput,
            SessionInfo,
            ToolCall,
        )

        evaluator = Evaluator(policies=load_bundle("eu_ai_act"))
        result = evaluator.evaluate(
            PolicyInput(
                agent=AgentInfo(id="a"),
                tool=ToolCall(name="calendar.read", arguments={"force": force}),
                session=SessionInfo(id="s"),
            )
        )
        assert result.matched_policy_id != "eu-ai-act-14-4d-block-human-override-flag"
