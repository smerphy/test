from __future__ import annotations

import pytest
from pydantic import ValidationError

from praetor_engine.predicates import (
    AlwaysPredicate,
    AndPredicate,
    EqPredicate,
    InPredicate,
    MatchesPredicate,
    NotPredicate,
    OrPredicate,
    parse_predicate,
)


class TestPathValidation:
    @pytest.mark.parametrize(
        "path",
        ["tool.name", "context.tenant_id", "agent.id", "session.parent_agent_ids"],
    )
    def test_accepts_dotted_identifiers(self, path: str) -> None:
        EqPredicate(path=path, value="x")

    @pytest.mark.parametrize(
        "path",
        ["", ".tool", "tool.", "tool..name", "1tool", "tool name", "tool/name"],
    )
    def test_rejects_malformed(self, path: str) -> None:
        with pytest.raises(ValidationError):
            EqPredicate(path=path, value="x")


class TestEqPredicate:
    def test_op_is_fixed(self) -> None:
        assert EqPredicate(path="tool.name", value="t").op == "eq"

    @pytest.mark.parametrize("value", ["s", 1, 1.5, True, None])
    def test_accepts_scalar_values(self, value: object) -> None:
        EqPredicate(path="tool.name", value=value)  # type: ignore[arg-type]

    def test_rejects_dict_value(self) -> None:
        with pytest.raises(ValidationError):
            EqPredicate(path="tool.name", value={"nested": 1})  # type: ignore[arg-type]


class TestInPredicate:
    def test_requires_at_least_one_value(self) -> None:
        with pytest.raises(ValidationError):
            InPredicate(path="tool.name", values=[])

    def test_construct(self) -> None:
        p = InPredicate(path="tool.name", values=["http.get", "http.post"])
        assert p.values == ["http.get", "http.post"]


class TestMatchesPredicate:
    def test_accepts_valid_regex(self) -> None:
        MatchesPredicate(path="tool.arguments.url", pattern=r"^https://")

    def test_rejects_invalid_regex(self) -> None:
        with pytest.raises(ValidationError) as exc:
            MatchesPredicate(path="tool.arguments.url", pattern="(unbalanced")
        assert "invalid regex" in str(exc.value)


class TestAlwaysPredicate:
    def test_takes_no_other_fields(self) -> None:
        assert AlwaysPredicate().op == "always"
        with pytest.raises(ValidationError):
            AlwaysPredicate(extra="boom")  # type: ignore[call-arg]


class TestCombinators:
    def test_and_requires_clauses(self) -> None:
        with pytest.raises(ValidationError):
            AndPredicate(clauses=[])

    def test_or_requires_clauses(self) -> None:
        with pytest.raises(ValidationError):
            OrPredicate(clauses=[])

    def test_not_is_unary(self) -> None:
        inner = EqPredicate(path="tool.name", value="t")
        assert NotPredicate(clause=inner).clause == inner

    def test_nested_tree(self) -> None:
        tree = AndPredicate(
            clauses=[
                EqPredicate(path="agent.id", value="agent-1"),
                OrPredicate(
                    clauses=[
                        EqPredicate(path="tool.name", value="http.get"),
                        InPredicate(path="tool.name", values=["fs.read", "fs.stat"]),
                    ]
                ),
                NotPredicate(
                    clause=MatchesPredicate(
                        path="tool.arguments.url", pattern=r"\.internal$"
                    )
                ),
            ]
        )
        # Frozen + JSON-round-trippable.
        dumped = tree.model_dump(mode="json")
        rebuilt = parse_predicate(dumped)
        assert rebuilt == tree


class TestDiscriminator:
    def test_dispatches_eq(self) -> None:
        p = parse_predicate({"op": "eq", "path": "tool.name", "value": "x"})
        assert isinstance(p, EqPredicate)

    def test_dispatches_and(self) -> None:
        p = parse_predicate(
            {
                "op": "and",
                "clauses": [
                    {"op": "eq", "path": "tool.name", "value": "x"},
                    {"op": "always"},
                ],
            }
        )
        assert isinstance(p, AndPredicate)
        assert isinstance(p.clauses[0], EqPredicate)
        assert isinstance(p.clauses[1], AlwaysPredicate)

    def test_rejects_unknown_op(self) -> None:
        with pytest.raises(ValidationError) as exc:
            parse_predicate({"op": "xor", "path": "tool.name", "value": "x"})
        assert "discriminator" in str(exc.value).lower() or "xor" in str(exc.value)

    def test_rejects_missing_op(self) -> None:
        with pytest.raises(ValidationError):
            parse_predicate({"path": "tool.name", "value": "x"})

    def test_rejects_extra_fields_per_node(self) -> None:
        with pytest.raises(ValidationError):
            parse_predicate(
                {"op": "eq", "path": "tool.name", "value": "x", "extra": True}
            )


class TestFrozen:
    def test_eq_predicate_frozen(self) -> None:
        p = EqPredicate(path="tool.name", value="x")
        with pytest.raises(ValidationError):
            p.value = "y"  # type: ignore[misc]
