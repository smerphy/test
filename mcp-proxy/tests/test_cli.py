"""CLI --check path (no MCP runtime required)."""

from __future__ import annotations

from pathlib import Path

import yaml

from praetor_mcp.__main__ import main

_CONFIG = {
    "agent": {"id": "a"},
    "enforcement": {"on_error": "deny"},
    "upstreams": [{"name": "fs", "transport": "stdio", "command": ["mcp-fs", "/data"]}],
    "listen": {"transport": "stdio"},
}


def test_cli_check_ok(tmp_path: Path, capsys) -> None:
    cfg = tmp_path / "praetor-mcp.yaml"
    cfg.write_text(yaml.safe_dump(_CONFIG))
    assert main(["--check", "-c", str(cfg)]) == 0
    assert "1 upstream" in capsys.readouterr().out


def test_cli_check_bad_config(tmp_path: Path, capsys) -> None:
    assert main(["--check", "-c", str(tmp_path / "missing.yaml")]) == 2
    assert "config error" in capsys.readouterr().err
