"""Predicate AST for the policy DSL.

This is the canonical AST that both the YAML surface and any future text
grammar (Rego-like, CEL-like, etc.) compile down to. The evaluator only
knows about this AST — parsers are kept downstream of it.

Design goals:
  - tagged union, dispatched on `op`, so adding a new operator is a
    purely additive change
  - JSON-serializable end to end (every field is a JSON scalar or
    another predicate)
  - frozen + extra="forbid" so policy bundles are reproducible and
    typos surface at parse time, not at evaluation time
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    field_validator,
)

_STRICT = ConfigDict(extra="forbid", frozen=True)

JsonScalar = str | int | float | bool | None
"""Permitted leaf value type for `eq` / `in` comparisons.

We intentionally do not allow dicts or lists here: equality on
structured values is rarely what authors actually want, and forcing
them to express it as nested predicates keeps the AST analyzable.
"""

_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


def _validate_path(value: str) -> str:
    if not _PATH_RE.match(value):
        raise ValueError(
            "path must be dotted identifiers (e.g. 'tool.name', "
            "'context.tenant_id'); no leading, trailing, or double dots"
        )
    return value


DottedPath = Annotated[str, AfterValidator(_validate_path)]


class EqPredicate(BaseModel):
    model_config = _STRICT

    op: Literal["eq"] = "eq"
    path: DottedPath
    value: JsonScalar


class InPredicate(BaseModel):
    model_config = _STRICT

    op: Literal["in"] = "in"
    path: DottedPath
    values: list[JsonScalar] = Field(..., min_length=1)


class MatchesPredicate(BaseModel):
    model_config = _STRICT

    op: Literal["matches"] = "matches"
    path: DottedPath
    pattern: str = Field(..., min_length=1)

    @field_validator("pattern")
    @classmethod
    def _compilable(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
        return value


class AlwaysPredicate(BaseModel):
    """Vacuous-true predicate. The only way to express an unconditional rule."""

    model_config = _STRICT

    op: Literal["always"] = "always"


class AndPredicate(BaseModel):
    model_config = _STRICT

    op: Literal["and"] = "and"
    clauses: list[Predicate] = Field(..., min_length=1)


class OrPredicate(BaseModel):
    model_config = _STRICT

    op: Literal["or"] = "or"
    clauses: list[Predicate] = Field(..., min_length=1)


class NotPredicate(BaseModel):
    model_config = _STRICT

    op: Literal["not"] = "not"
    clause: Predicate


Predicate = Annotated[
    EqPredicate
    | InPredicate
    | MatchesPredicate
    | AlwaysPredicate
    | AndPredicate
    | OrPredicate
    | NotPredicate,
    Field(discriminator="op"),
]

# Resolve forward references on combinators (list["Predicate"] / "Predicate").
AndPredicate.model_rebuild()
OrPredicate.model_rebuild()
NotPredicate.model_rebuild()

_PREDICATE_ADAPTER: TypeAdapter[
    EqPredicate
    | InPredicate
    | MatchesPredicate
    | AlwaysPredicate
    | AndPredicate
    | OrPredicate
    | NotPredicate
] = TypeAdapter(Predicate)


def parse_predicate(
    data: object,
) -> (
    EqPredicate
    | InPredicate
    | MatchesPredicate
    | AlwaysPredicate
    | AndPredicate
    | OrPredicate
    | NotPredicate
):
    """Parse a raw dict / JSON-decoded value into a concrete predicate node."""
    return _PREDICATE_ADAPTER.validate_python(data)


__all__ = [
    "AlwaysPredicate",
    "AndPredicate",
    "DottedPath",
    "EqPredicate",
    "InPredicate",
    "JsonScalar",
    "MatchesPredicate",
    "NotPredicate",
    "OrPredicate",
    "Predicate",
    "parse_predicate",
]
