from __future__ import annotations

from pathlib import Path

import pytest

from ephorate_engine.evaluator import Policy
from ephorate_engine.parser import PolicyParseError, parse_bundle, parse_bundle_file
from ephorate_engine.predicates import AndPredicate, EqPredicate
from ephorate_engine.types import Decision

GOOD_BUNDLE = """\
policies:
  - id: allow-fs-read
    effect: allow
    when:
      op: eq
      path: tool.name
      value: fs.read
    reason: filesystem reads allowed
    metadata:
      nist_ai_rmf: GOVERN-1.1

  - id: deny-internal-http
    effect: deny
    when:
      op: and
      clauses:
        - op: eq
          path: tool.name
          value: http.get
        - op: matches
          path: tool.arguments.url
          pattern: '\\.internal($|/)'
    reason: internal hosts must not be hit by agents
"""


class TestParseBundle:
    def test_parses_well_formed_bundle(self) -> None:
        policies = parse_bundle(GOOD_BUNDLE)
        assert len(policies) == 2
        assert policies[0].id == "allow-fs-read"
        assert policies[0].effect is Decision.ALLOW
        assert isinstance(policies[0].when, EqPredicate)
        assert policies[0].metadata == {"nist_ai_rmf": "GOVERN-1.1"}

        assert policies[1].id == "deny-internal-http"
        assert isinstance(policies[1].when, AndPredicate)

    def test_empty_text_yields_no_policies(self) -> None:
        assert parse_bundle("") == []

    def test_missing_policies_key_yields_no_policies(self) -> None:
        assert parse_bundle("version: 1\n") == []

    def test_non_mapping_root_rejected(self) -> None:
        with pytest.raises(PolicyParseError, match="mapping"):
            parse_bundle("- not a mapping\n")

    def test_policies_not_a_list_rejected(self) -> None:
        with pytest.raises(PolicyParseError, match="must be a list"):
            parse_bundle("policies: 1\n")

    def test_invalid_yaml_raises_parse_error(self) -> None:
        with pytest.raises(PolicyParseError, match="invalid YAML"):
            parse_bundle("policies:\n  - id: x\n   bad indent\n")

    def test_invalid_policy_includes_index(self) -> None:
        with pytest.raises(PolicyParseError, match="policy at index 0"):
            parse_bundle(
                "policies:\n  - id: p\n    effect: allow\n    when:\n      op: always\n"
            )  # missing 'reason'

    def test_invalid_predicate_op_rejected(self) -> None:
        with pytest.raises(PolicyParseError, match="policy at index 0"):
            parse_bundle(
                "policies:\n"
                "  - id: p\n"
                "    effect: allow\n"
                "    when:\n"
                "      op: xor\n"
                "      path: tool.name\n"
                "      value: x\n"
                "    reason: r\n"
            )

    def test_duplicate_ids_rejected(self) -> None:
        text = (
            "policies:\n"
            "  - {id: p, effect: allow, reason: r, when: {op: always}}\n"
            "  - {id: p, effect: deny, reason: r, when: {op: always}}\n"
        )
        with pytest.raises(PolicyParseError, match="duplicate policy id"):
            parse_bundle(text)


class TestParseBundleFile:
    def test_round_trip_through_file(self, tmp_path: Path) -> None:
        p = tmp_path / "bundle.yaml"
        p.write_text(GOOD_BUNDLE)
        policies = parse_bundle_file(p)
        assert [pol.id for pol in policies] == [
            "allow-fs-read",
            "deny-internal-http",
        ]
        assert all(isinstance(pol, Policy) for pol in policies)
