"""Benchmark harness for the evaluator.

Spec target: sub-5ms p99 on a 100-policy bundle. Today the evaluator is a
stub (raises NotImplementedError), so the benchmark fails fast — that
failure is the reminder to implement it. Once `Evaluator.evaluate` lands,
enable a hard p99 ceiling via pytest-benchmark's `--benchmark-max-time`
or a custom comparison against a stored baseline.
"""

from __future__ import annotations

import pytest

from praetor_engine.evaluator import Evaluator, Policy
from praetor_engine.predicates import EqPredicate, Predicate
from praetor_engine.types import (
    AgentInfo,
    Decision,
    PolicyInput,
    SessionInfo,
    ToolCall,
)


def _bundle(size: int) -> list[Policy]:
    policies: list[Policy] = []
    for i in range(size):
        when: Predicate = EqPredicate(path="tool.name", value=f"tool-{i}")
        effect = Decision.ALLOW if i % 2 == 0 else Decision.DENY
        policies.append(
            Policy(id=f"p-{i}", effect=effect, when=when, reason=f"rule {i}")
        )
    return policies


@pytest.fixture
def hundred_policy_evaluator() -> Evaluator:
    return Evaluator(policies=_bundle(100))


@pytest.fixture
def sample_input() -> PolicyInput:
    return PolicyInput(
        agent=AgentInfo(id="agent-1"),
        tool=ToolCall(name="tool-42", arguments={}),
        session=SessionInfo(id="sess-1"),
    )


@pytest.mark.xfail(
    strict=True,
    raises=NotImplementedError,
    reason="evaluator stub — remove this marker when Evaluator.evaluate is implemented",
)
@pytest.mark.benchmark(group="evaluator")
def test_evaluate_100_policy_bundle(
    benchmark: pytest.FixtureRequest,
    hundred_policy_evaluator: Evaluator,
    sample_input: PolicyInput,
) -> None:
    benchmark(hundred_policy_evaluator.evaluate, sample_input)  # type: ignore[operator]
