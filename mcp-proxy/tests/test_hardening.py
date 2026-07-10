"""Production hardening: env expansion, downstream auth, per-session identity,
health endpoints, graceful drain."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ephorate_mcp.auth import BearerAuthMiddleware
from ephorate_mcp.config import load_config, parse_config
from ephorate_mcp.identity import Identity, current_identity, set_identity


# --- #3 env-var expansion ---------------------------------------------------
def test_config_expands_env_vars(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MY_TOKEN", "s3cr3t")
    monkeypatch.setenv("MY_URL", "https://cp.example")
    cfg_path = tmp_path / "ephorate-mcp.yaml"
    # Env refs are expanded after the YAML is parsed, so use block style (or
    # quote them in flow style) — `${VAR}` is not a bare YAML flow scalar.
    cfg_path.write_text(
        "control_plane:\n  url: ${MY_URL}\n  api_key: ${MY_TOKEN}\n"
        "upstreams:\n"
        "  - name: gh\n    transport: stdio\n    command: [srv]\n"
        "    env:\n      TOKEN: ${MY_TOKEN}\n"
    )
    cfg = load_config(cfg_path)
    assert cfg.api_key == "s3cr3t"
    assert cfg.control_plane_url == "https://cp.example"
    assert cfg.upstreams[0].env["TOKEN"] == "s3cr3t"


def test_env_value_cannot_inject_yaml_structure(monkeypatch, tmp_path: Path) -> None:
    # An env var whose value contains YAML syntax must become a scalar string,
    # not extra config structure (expansion happens after parsing).
    monkeypatch.setenv("EVIL", "real\nadmin_backdoor: true")
    cfg_path = tmp_path / "evil.yaml"
    cfg_path.write_text(
        "agent:\n  id: ${EVIL}\n"
        "upstreams:\n  - name: x\n    transport: stdio\n    command: [a]\n"
    )
    cfg = load_config(cfg_path)
    assert cfg.agent_id == "real\nadmin_backdoor: true"  # inert scalar
    assert not hasattr(cfg, "admin_backdoor")


def test_undefined_env_var_left_intact(tmp_path: Path) -> None:
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text(
        "agent:\n  id: ${NOT_SET_XYZ}\n"
        "upstreams:\n  - name: x\n    transport: stdio\n    command: [a]\n"
    )
    assert load_config(cfg_path).agent_id == "${NOT_SET_XYZ}"


def test_auth_tokens_parsed() -> None:
    cfg = parse_config(
        {
            "upstreams": [{"name": "x", "transport": "stdio", "command": ["a"]}],
            "listen": {"auth_tokens": {"tok-a": "agent-a", "tok-b": "agent-b"}},
        }
    )
    assert cfg.listen_auth_tokens == {"tok-a": "agent-a", "tok-b": "agent-b"}


# --- identity contextvar ----------------------------------------------------
def test_identity_contextvar_roundtrip() -> None:
    assert current_identity() is None
    set_identity(Identity(session_id="s", agent_id="a"))
    try:
        idn = current_identity()
        assert idn is not None and idn.agent_id == "a" and idn.session_id == "s"
    finally:
        set_identity(None)
    assert current_identity() is None


# --- #2 downstream auth middleware (pure ASGI) ------------------------------
async def _drive(
    app: Any, headers: list[tuple[bytes, bytes]], path: str = "/mcp"
) -> dict[str, Any]:
    """Minimal ASGI driver: returns {status, body}."""
    scope = {"type": "http", "method": "GET", "path": path, "headers": headers}
    captured: dict[str, Any] = {}

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    sent: list[dict[str, Any]] = []

    async def send(msg: dict[str, Any]) -> None:
        sent.append(msg)

    await app(scope, receive, send)
    start = next((m for m in sent if m["type"] == "http.response.start"), {})
    body = b"".join(
        m.get("body", b"") for m in sent if m["type"] == "http.response.body"
    )
    captured["status"] = start.get("status")
    captured["body"] = body
    return captured


async def test_auth_rejects_without_token() -> None:
    async def _inner(scope: Any, receive: Any, send: Any) -> None:  # pragma: no cover
        raise AssertionError("inner app must not run for a rejected request")

    app = BearerAuthMiddleware(_inner, {"good": "agent-1"})
    r = await _drive(app, headers=[])
    assert r["status"] == 401
    r = await _drive(app, headers=[(b"authorization", b"Bearer wrong")])
    assert r["status"] == 401


async def test_auth_passes_and_sets_identity() -> None:
    seen: dict[str, Any] = {}

    async def _inner(scope: Any, receive: Any, send: Any) -> None:
        idn = current_identity()
        seen["agent"] = idn.agent_id if idn else None
        seen["session"] = idn.session_id if idn else None
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = BearerAuthMiddleware(_inner, {"good": "agent-1"})
    r = await _drive(
        app,
        headers=[
            (b"authorization", b"Bearer good"),
            (b"mcp-session-id", b"sess-42"),
        ],
    )
    assert r["status"] == 200
    assert seen == {"agent": "agent-1", "session": "sess-42"}
    # Identity is cleared after the request.
    assert current_identity() is None


async def test_auth_session_falls_back_to_agent() -> None:
    seen: dict[str, Any] = {}

    async def _inner(scope: Any, receive: Any, send: Any) -> None:
        idn = current_identity()
        seen["session"] = idn.session_id if idn else None
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app = BearerAuthMiddleware(_inner, {"good": "agent-1"})
    await _drive(app, headers=[(b"authorization", b"Bearer good")])
    assert seen["session"] == "agent:agent-1"


# --- #1 gate uses the per-request identity ----------------------------------
def test_proxy_uses_contextvar_identity() -> None:
    pytest.importorskip("mcp")
    from ephorate_mcp.server import ProxyServer

    proxy = ProxyServer(
        parse_config(
            {
                "agent": {"id": "config-agent"},
                "upstreams": [{"name": "x", "transport": "stdio", "command": ["a"]}],
            }
        )
    )
    # Default (stdio) identity comes from config.
    assert proxy._identity().agent_id == "config-agent"
    # A per-request identity (set by the middleware) takes precedence.
    set_identity(Identity(session_id="sess", agent_id="http-agent"))
    try:
        assert proxy._identity().agent_id == "http-agent"
        assert proxy._identity().session_id == "sess"
    finally:
        set_identity(None)


# --- #4 health + graceful drain ---------------------------------------------
def _app_for_health() -> Any:
    from ephorate_mcp.server import build_asgi_app

    return build_asgi_app(
        parse_config(
            {
                "agent": {"id": "a"},
                "upstreams": [{"name": "x", "transport": "stdio", "command": ["a"]}],
            }
        )
    )


async def test_healthz_ok() -> None:
    pytest.importorskip("mcp")
    # Drive the http route directly (no lifespan → no upstream connect).
    r = await _drive(_app_for_health(), headers=[], path="/healthz")
    assert r["status"] == 200 and r["body"] == b"ok"


async def test_readyz_starting_before_upstreams() -> None:
    pytest.importorskip("mcp")
    # Upstreams are connected in the lifespan; before that, not ready.
    r = await _drive(_app_for_health(), headers=[], path="/readyz")
    assert r["status"] == 503


def test_gate_close_flushes_client() -> None:
    from ephorate_mcp.gate import PolicyGate

    calls: list[str] = []

    class _Client:
        policies: tuple[Any, ...] = ()

        def stop(self) -> None:
            calls.append("stop")

    PolicyGate(_Client()).close()
    assert calls == ["stop"]
