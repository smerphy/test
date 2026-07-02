from __future__ import annotations

import json
from pathlib import Path

import pytest

from praetor_engine.cli import (
    EXIT_ALLOW,
    EXIT_BAD_INPUT,
    EXIT_DENY,
    EXIT_OK,
    EXIT_REQUIRE_APPROVAL,
    EXIT_TRANSFORM,
    main,
)


def _write_bundle(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "bundle.yaml"
    p.write_text(text)
    return p


def _write_input(tmp_path: Path, tool_name: str = "http.get") -> Path:
    p = tmp_path / "input.json"
    p.write_text(
        json.dumps(
            {
                "agent": {"id": "agent-1"},
                "tool": {"name": tool_name, "arguments": {"url": "https://x.example.com"}},
                "session": {"id": "sess-1"},
            }
        )
    )
    return p


ALLOW_BUNDLE = (
    "policies:\n"
    "  - id: allow-http\n"
    "    effect: allow\n"
    "    when: {op: eq, path: tool.name, value: http.get}\n"
    "    reason: ok\n"
)

DENY_BUNDLE = (
    "policies:\n"
    "  - id: deny-http\n"
    "    effect: deny\n"
    "    when: {op: eq, path: tool.name, value: http.get}\n"
    "    reason: nope\n"
)

TRANSFORM_BUNDLE = (
    "policies:\n"
    "  - id: redact\n"
    "    effect: transform\n"
    "    when: {op: always}\n"
    "    reason: redact\n"
    "    transform: {url: <redacted>}\n"
)

REQUIRE_APPROVAL_BUNDLE = (
    "policies:\n"
    "  - id: human-in-the-loop\n"
    "    effect: require_approval\n"
    "    when: {op: always}\n"
    "    reason: needs human\n"
)


class TestEvalCommand:
    def test_allow_exit_zero_and_json_on_stdout(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            [
                "eval",
                "--policy",
                str(_write_bundle(tmp_path, ALLOW_BUNDLE)),
                "--input",
                str(_write_input(tmp_path)),
            ]
        )
        assert rc == EXIT_ALLOW
        out = capsys.readouterr().out
        result = json.loads(out)
        assert result["decision"] == "allow"
        assert result["matched_policy_id"] == "allow-http"

    def test_deny_exits_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            [
                "eval",
                "--policy",
                str(_write_bundle(tmp_path, DENY_BUNDLE)),
                "--input",
                str(_write_input(tmp_path)),
            ]
        )
        assert rc == EXIT_DENY
        assert json.loads(capsys.readouterr().out)["decision"] == "deny"

    def test_default_deny_when_no_policy_matches(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            [
                "eval",
                "--policy",
                str(_write_bundle(tmp_path, ALLOW_BUNDLE)),
                "--input",
                str(_write_input(tmp_path, tool_name="fs.read")),
            ]
        )
        assert rc == EXIT_DENY
        result = json.loads(capsys.readouterr().out)
        assert result["decision"] == "deny"
        assert result["matched_policy_id"] is None

    def test_transform_exits_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            [
                "eval",
                "--policy",
                str(_write_bundle(tmp_path, TRANSFORM_BUNDLE)),
                "--input",
                str(_write_input(tmp_path)),
            ]
        )
        assert rc == EXIT_TRANSFORM
        result = json.loads(capsys.readouterr().out)
        assert result["decision"] == "transform"
        assert result["suggested_transform"] == {"url": "<redacted>"}

    def test_require_approval_exits_three(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            [
                "eval",
                "--policy",
                str(_write_bundle(tmp_path, REQUIRE_APPROVAL_BUNDLE)),
                "--input",
                str(_write_input(tmp_path)),
            ]
        )
        assert rc == EXIT_REQUIRE_APPROVAL
        assert json.loads(capsys.readouterr().out)["decision"] == "require_approval"


class TestEvalErrors:
    def test_missing_policy_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            [
                "eval",
                "--policy",
                str(tmp_path / "missing.yaml"),
                "--input",
                str(_write_input(tmp_path)),
            ]
        )
        assert rc == EXIT_BAD_INPUT
        assert "policy file not found" in capsys.readouterr().err

    def test_malformed_policy_bundle(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            [
                "eval",
                "--policy",
                str(_write_bundle(tmp_path, "policies: 1\n")),
                "--input",
                str(_write_input(tmp_path)),
            ]
        )
        assert rc == EXIT_BAD_INPUT
        assert "must be a list" in capsys.readouterr().err

    def test_missing_input_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            [
                "eval",
                "--policy",
                str(_write_bundle(tmp_path, ALLOW_BUNDLE)),
                "--input",
                str(tmp_path / "missing.json"),
            ]
        )
        assert rc == EXIT_BAD_INPUT
        assert "input file not found" in capsys.readouterr().err

    def test_invalid_json_input(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad = tmp_path / "input.json"
        bad.write_text("{not json")
        rc = main(
            [
                "eval",
                "--policy",
                str(_write_bundle(tmp_path, ALLOW_BUNDLE)),
                "--input",
                str(bad),
            ]
        )
        assert rc == EXIT_BAD_INPUT
        assert "invalid JSON" in capsys.readouterr().err

    def test_invalid_policy_input_shape(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad = tmp_path / "input.json"
        bad.write_text(json.dumps({"agent": {}, "tool": {}, "session": {}}))
        rc = main(
            [
                "eval",
                "--policy",
                str(_write_bundle(tmp_path, ALLOW_BUNDLE)),
                "--input",
                str(bad),
            ]
        )
        assert rc == EXIT_BAD_INPUT
        assert "invalid PolicyInput" in capsys.readouterr().err


class TestValidateCommand:
    def test_valid_bundle_emits_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["validate", "--policy", str(_write_bundle(tmp_path, ALLOW_BUNDLE))])
        assert rc == EXIT_OK
        summary = json.loads(capsys.readouterr().out)
        assert summary["policy_count"] == 1
        assert summary["policies"][0]["id"] == "allow-http"
        assert summary["policies"][0]["effect"] == "allow"

    def test_invalid_bundle_returns_64(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(
            ["validate", "--policy", str(_write_bundle(tmp_path, "policies: 1\n"))]
        )
        assert rc == EXIT_BAD_INPUT
        assert "must be a list" in capsys.readouterr().err

    def test_missing_bundle_returns_64(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["validate", "--policy", str(tmp_path / "nope.yaml")])
        assert rc == EXIT_BAD_INPUT


class TestListBundlesCommand:
    def test_lists_starter_bundles(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["list-bundles"])
        assert rc == EXIT_OK
        names = json.loads(capsys.readouterr().out)
        assert set(names) >= {"nist_ai_rmf", "iso_42001", "eu_ai_act"}
