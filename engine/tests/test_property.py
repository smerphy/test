"""Property-based tests using Hypothesis.

Covers invariants that hand-written tests can only spot-check:
  - predicate JSON round-trip is identity
  - evaluator is deterministic across repeated calls
  - evaluator does not mutate its input
  - adding a deny rule never downgrades the resulting decision
"""

from __future__ import annotations

import string

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from praetor_engine.evaluator import Evaluator, Policy
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
from praetor_engine.types import (
    AgentInfo,
    Decision,
    PolicyInput,
    SessionInfo,
    ToolCall,
)

_ident = st.text(alphabet=string.ascii_lowercase + "_", min_size=1, max_size=6)
_path = st.builds(
    lambda parts: ".".join(parts),
    st.lists(_ident, min_size=1, max_size=3),
)
_scalar = st.one_of(
    st.text(max_size=8),
    st.integers(min_value=-1000, max_value=1000),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.booleans(),
    st.none(),
)
_safe_regex = st.sampled_from(
    [r"^http", r"\d+", r"foo|bar", r"[a-z]+", r"^$", r"\.internal$"]
)

_leaf_predicate = st.one_of(
    st.builds(EqPredicate, path=_path, value=_scalar),
    st.builds(
        InPredicate,
        path=_path,
        values=st.lists(_scalar, min_size=1, max_size=4),
    ),
    st.builds(MatchesPredicate, path=_path, pattern=_safe_regex),
    st.builds(AlwaysPredicate),
)

_predicate = st.recursive(
    _leaf_predicate,
    lambda children: st.one_of(
        st.builds(
            AndPredicate, clauses=st.lists(children, min_size=1, max_size=3)
        ),
        st.builds(
            OrPredicate, clauses=st.lists(children, min_size=1, max_size=3)
        ),
        st.builds(NotPredicate, clause=children),
    ),
    max_leaves=8,
)

_args_dict = st.dictionaries(_ident, _scalar, max_size=3)
_policy_input = st.builds(
    PolicyInput,
    agent=st.builds(AgentInfo, id=_ident),
    tool=st.builds(ToolCall, name=_ident, arguments=_args_dict),
    session=st.builds(SessionInfo, id=_ident),
    context=_args_dict,
)

_PROPERTY_SETTINGS = settings(
    max_examples=75,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


@_PROPERTY_SETTINGS
@given(_predicate)
def test_predicate_json_round_trip_is_identity(p: object) -> None:
    rebuilt = parse_predicate(p.model_dump(mode="json"))  # type: ignore[attr-defined]
    assert rebuilt == p


@_PROPERTY_SETTINGS
@given(_predicate, _policy_input)
def test_evaluator_is_deterministic(p: object, pi: PolicyInput) -> None:
    policy = Policy(
        id="p",
        effect=Decision.ALLOW,
        when=p,  # type: ignore[arg-type]
        reason="r",
    )
    ev = Evaluator(policies=[policy])
    assert ev.evaluate(pi) == ev.evaluate(pi)


@_PROPERTY_SETTINGS
@given(_predicate, _policy_input)
def test_evaluator_does_not_mutate_input(p: object, pi: PolicyInput) -> None:
    policy = Policy(
        id="p",
        effect=Decision.ALLOW,
        when=p,  # type: ignore[arg-type]
        reason="r",
    )
    before = pi.model_dump()
    Evaluator(policies=[policy]).evaluate(pi)
    assert pi.model_dump() == before


@_PROPERTY_SETTINGS
@given(_predicate, _policy_input)
def test_appending_always_deny_forces_deny(p: object, pi: PolicyInput) -> None:
    """Deny has highest precedence: adding an always-deny rule must yield deny."""
    base = Policy(
        id="base",
        effect=Decision.ALLOW,
        when=p,  # type: ignore[arg-type]
        reason="base",
    )
    deny = Policy(
        id="deny",
        effect=Decision.DENY,
        when=AlwaysPredicate(),
        reason="deny",
    )
    result = Evaluator(policies=[base, deny]).evaluate(pi)
    assert result.decision is Decision.DENY
    assert result.matched_policy_id == "deny"
