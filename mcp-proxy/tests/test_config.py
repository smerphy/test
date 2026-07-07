"""Config parsing/validation + client construction."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ephorate_mcp.config import build_client, load_config, parse_config


def _doc() -> dict:
    return {
        "control_plane": {"url": "https://cp.example", "api_key": "k", "org_slug": "acme"},
        "policy": {"bundle_path": None},
        "agent": {"id": "research-agent-1"},
        "enforcement": {"on_error": "deny", "approval_timeout_seconds": 120},
        "upstreams": [
            {"name": "github", "transport": "stdio", "command": ["npx", "server-github"]},
            {"name": "api", "transport": "streamable-http", "url": "https://tools.example/mcp"},
        ],
        "listen": {"transport": "stdio"},
    }


def test_parse_full_config() -> None:
    cfg = parse_config(_doc())
    assert cfg.agent_id == "research-agent-1"
    assert cfg.control_plane_url == "https://cp.example"
    assert cfg.enforcement.approval_timeout_seconds == 120
    assert [u.name for u in cfg.upstreams] == ["github", "api"]
    assert cfg.listen_transport == "stdio"


def test_validation_errors() -> None:
    with pytest.raises(ValueError, match="at least one upstream"):
        parse_config({"upstreams": []})
    with pytest.raises(ValueError, match="stdio requires a command"):
        parse_config({"upstreams": [{"name": "x", "transport": "stdio"}]})
    with pytest.raises(ValueError, match="streamable-http requires a url"):
        parse_config({"upstreams": [{"name": "x", "transport": "streamable-http"}]})
    with pytest.raises(ValueError, match="on_error"):
        parse_config(
            {
                "upstreams": [{"name": "x", "transport": "stdio", "command": ["a"]}],
                "enforcement": {"on_error": "sometimes"},
            }
        )


def test_load_config_from_file(tmp_path: Path) -> None:
    path = tmp_path / "ephorate-mcp.yaml"
    path.write_text(yaml.safe_dump(_doc()))
    cfg = load_config(path)
    assert cfg.org_slug == "acme"


def test_build_client_uses_policies(tmp_path: Path) -> None:
    bundle = tmp_path / "policies.yaml"
    bundle.write_text(
        "policies:\n"
        "  - id: allow-get\n"
        "    effect: allow\n"
        "    when: { op: eq, path: tool.name, value: get }\n"
        "    reason: ok\n"
    )
    cfg = parse_config(
        {
            "policy": {"bundle_path": str(bundle)},
            "agent": {"id": "a"},
            "audit_log_path": str(tmp_path / "audit.jsonl"),
            "upstreams": [{"name": "x", "transport": "stdio", "command": ["a"]}],
        }
    )
    client = build_client(cfg)
    assert [p.id for p in client.policies] == ["allow-get"]
