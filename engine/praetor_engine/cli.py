"""Praetor CLI.

Sub-commands:

    praetor eval     --policy bundle.yaml --input input.json
    praetor validate --policy bundle.yaml
    praetor list-bundles

Writes results as JSON to stdout. Exit codes encode the result so
callers can branch without parsing stdout:

    0 = success / allow
    1 = deny (explicit rule or default-deny)
    2 = transform suggested
    3 = require_approval
    64 = bad input (malformed policy or PolicyInput) — sysexits.h EX_USAGE
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from praetor_engine.bundles import list_bundles
from praetor_engine.evaluator import Evaluator, Policy
from praetor_engine.parser import PolicyParseError, parse_bundle_file
from praetor_engine.types import Decision, PolicyInput

EXIT_OK: Final[int] = 0
EXIT_ALLOW: Final[int] = 0
EXIT_DENY: Final[int] = 1
EXIT_TRANSFORM: Final[int] = 2
EXIT_REQUIRE_APPROVAL: Final[int] = 3
EXIT_BAD_INPUT: Final[int] = 64

_DECISION_EXIT: dict[Decision, int] = {
    Decision.ALLOW: EXIT_ALLOW,
    Decision.DENY: EXIT_DENY,
    Decision.TRANSFORM: EXIT_TRANSFORM,
    Decision.REQUIRE_APPROVAL: EXIT_REQUIRE_APPROVAL,
}


def _load_policies(path: Path) -> tuple[list[Policy], int]:
    """Load + parse a bundle; on error, write to stderr and return ([], exit_code).

    Returns (policies, 0) on success.
    """
    try:
        policies = parse_bundle_file(path)
        return policies, EXIT_OK
    except FileNotFoundError as exc:
        print(f"error: policy file not found: {exc}", file=sys.stderr)
        return [], EXIT_BAD_INPUT
    except PolicyParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return [], EXIT_BAD_INPUT


def _eval_cmd(args: argparse.Namespace) -> int:
    policies, rc = _load_policies(args.policy)
    if rc != EXIT_OK:
        return rc

    try:
        raw_input = json.loads(args.input.read_text())
    except FileNotFoundError as exc:
        print(f"error: input file not found: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON input: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT

    try:
        policy_input = PolicyInput.model_validate(raw_input)
    except ValidationError as exc:
        print(f"error: invalid PolicyInput: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT

    result = Evaluator(policies=policies).evaluate(policy_input)
    sys.stdout.write(result.model_dump_json(indent=2) + "\n")
    return _DECISION_EXIT[result.decision]


def _validate_cmd(args: argparse.Namespace) -> int:
    policies, rc = _load_policies(args.policy)
    if rc != EXIT_OK:
        return rc

    summary = {
        "policy_count": len(policies),
        "policies": [
            {
                "id": p.id,
                "effect": p.effect.value,
                "metadata": p.metadata,
            }
            for p in policies
        ],
    }
    sys.stdout.write(json.dumps(summary, indent=2) + "\n")
    return EXIT_OK


def _list_bundles_cmd(args: argparse.Namespace) -> int:
    sys.stdout.write(json.dumps(list_bundles(), indent=2) + "\n")
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="praetor",
        description="Praetor policy engine CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser(
        "eval",
        help="Evaluate a PolicyInput against a YAML policy bundle",
    )
    ev.add_argument(
        "--policy",
        required=True,
        type=Path,
        help="Path to YAML policy bundle",
    )
    ev.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to JSON-encoded PolicyInput",
    )
    ev.set_defaults(func=_eval_cmd)

    vd = sub.add_parser(
        "validate",
        help="Parse + validate a YAML policy bundle. Exits 64 on errors.",
    )
    vd.add_argument(
        "--policy", required=True, type=Path, help="Path to YAML policy bundle"
    )
    vd.set_defaults(func=_validate_cmd)

    lb = sub.add_parser(
        "list-bundles",
        help="List the starter compliance bundles shipped with the engine.",
    )
    lb.set_defaults(func=_list_bundles_cmd)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
