"""Performance budget tests for the evaluator.

Spec target: sub-5ms p99 on a 100-policy bundle. The first test below
enforces this budget in CI directly; the pytest-benchmark variant is
also wired up so engineers can profile locally with
`--benchmark-enable`.

If `test_evaluate_p99_under_budget` becomes flaky on shared CI runners,
raise `P99_BUDGET_MS` and file a follow-up to switch to baseline-
comparison via pytest-benchmark's `--benchmark-compare-fail`.
"""

from __future__ import annotations

import time
from typing import Final

import pytest

from praetor_engine.evaluator import Evaluator, Policy
from praetor_engine.predicates import AndPredicate, EqPredicate, MatchesPredicate
from praetor_engine.types import (
    AgentInfo,
    Decision,
    PolicyInput,
    SessionInfo,
    ToolCall,
)

P99_BUDGET_MS: Final[float] = 5.0
SAMPLES: Final[int] = 1000
WARMUP: Final[int] = 100


def _bundle(size: int) -> list[Policy]:
    """A mixed 100-policy bundle: eq + and(eq, matches), alternating effects."""
    policies: list[Policy] = []
    for i in range(size):
        if i % 3 == 0:
            when = AndPredicate(
                clauses=[
                    EqPredicate(path="tool.name", value=f"tool-{i}"),
                    MatchesPredicate(
                        path="tool.arguments.url", pattern=r"^https://"
                    ),
                ]
            )
        else:
            when = EqPredicate(path="tool.name", value=f"tool-{i}")
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
        tool=ToolCall(
            name="tool-42", arguments={"url": "https://example.com"}
        ),
        session=SessionInfo(id="sess-1"),
    )


def test_evaluate_p99_under_budget(
    hundred_policy_evaluator: Evaluator, sample_input: PolicyInput
) -> None:
    # Warm-up: amortize regex compilation and first-call dispatch.
    for _ in range(WARMUP):
        hundred_policy_evaluator.evaluate(sample_input)

    elapsed_ns: list[int] = []
    for _ in range(SAMPLES):
        t0 = time.perf_counter_ns()
        hundred_policy_evaluator.evaluate(sample_input)
        elapsed_ns.append(time.perf_counter_ns() - t0)

    elapsed_ns.sort()
    p99_ns = elapsed_ns[int(0.99 * SAMPLES)]
    p99_ms = p99_ns / 1_000_000
    assert p99_ms < P99_BUDGET_MS, (
        f"p99 = {p99_ms:.3f}ms exceeds budget of {P99_BUDGET_MS}ms"
    )


@pytest.mark.benchmark(group="evaluator")
def test_evaluate_100_policy_bundle(
    benchmark: pytest.FixtureRequest,
    hundred_policy_evaluator: Evaluator,
    sample_input: PolicyInput,
) -> None:
    benchmark(hundred_policy_evaluator.evaluate, sample_input)  # type: ignore[operator]
