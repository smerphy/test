"""YAML parser for Praetor policy bundles.

Parses the concrete YAML surface syntax into the AST defined by
`praetor_engine.evaluator.Policy` and `praetor_engine.predicates`. Any
future text grammar (Rego-like, CEL-like) should compile down to the
same AST and reuse the same downstream evaluator.

Bundle shape:

    policies:
      - id: allow-fs-read
        effect: allow
        when:
          op: eq
          path: tool.name
          value: fs.read
        reason: filesystem reads are on the allowlist
        metadata:
          nist_ai_rmf: GOVERN-1.1
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from praetor_engine.evaluator import Policy


class PolicyParseError(ValueError):
    """Raised when a policy bundle fails to parse or validate."""


def parse_bundle(text: str) -> list[Policy]:
    """Parse a YAML bundle into a list of `Policy`. Empty bundles are legal."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyParseError(f"invalid YAML: {exc}") from exc

    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise PolicyParseError(
            "bundle must be a YAML mapping with a top-level 'policies' key"
        )

    policies_raw = raw.get("policies")
    if policies_raw is None:
        return []
    if not isinstance(policies_raw, list):
        raise PolicyParseError("'policies' must be a list")

    policies: list[Policy] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(policies_raw):
        try:
            policy = Policy.model_validate(entry)
        except ValidationError as exc:
            raise PolicyParseError(f"policy at index {index}: {exc}") from exc
        if policy.id in seen_ids:
            raise PolicyParseError(
                f"duplicate policy id {policy.id!r} (first wins is too easy "
                "to mis-author; declare unique ids)"
            )
        seen_ids.add(policy.id)
        policies.append(policy)
    return policies


def parse_bundle_file(path: Path | str) -> list[Policy]:
    # Accept a plain string too — the documented quickstart passes one.
    return parse_bundle(Path(path).read_text())


__all__ = ["PolicyParseError", "parse_bundle", "parse_bundle_file"]
