"""Streamable-HTTP listen transport (ASGI deployment mode)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")

from praetor_mcp.config import parse_config
from praetor_mcp.server import build_asgi_app


def _config(tmp_path: Path, path: str = "/mcp") -> Any:
    return parse_config(
        {
            "agent": {"id": "a"},
            "audit_log_path": str(tmp_path / "audit.jsonl"),
            "upstreams": [{"name": "mock", "transport": "stdio", "command": ["x"]}],
            "listen": {"transport": "streamable-http", "bind": "0.0.0.0:9000", "path": path},
        }
    )


def test_listen_path_parsed() -> None:
    cfg = parse_config(
        {
            "upstreams": [{"name": "x", "transport": "stdio", "command": ["a"]}],
            "listen": {"transport": "streamable-http", "path": "/agent-gw"},
        }
    )
    assert cfg.listen_path == "/agent-gw"
    assert cfg.listen_transport == "streamable-http"


def test_build_asgi_app_mounts_configured_path(tmp_path: Path) -> None:
    app = build_asgi_app(_config(tmp_path, path="/mcp"))
    mounted = [getattr(r, "path", None) for r in app.routes]
    assert "/mcp" in mounted


def test_build_asgi_app_custom_path(tmp_path: Path) -> None:
    app = build_asgi_app(_config(tmp_path, path="/agent-gw"))
    mounted = [getattr(r, "path", None) for r in app.routes]
    assert "/agent-gw" in mounted
    # A Starlette app with a lifespan is returned (upstreams connect on startup).
    assert app.router.lifespan_context is not None
