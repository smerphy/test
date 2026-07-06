"""Reliability + observability: metrics, upstream reconnect-retry, /metrics,
DNS-rebinding settings."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from praetor_engine.evaluator import Policy
from praetor_engine.predicates import EqPredicate
from praetor_engine.types import Decision

from praetor_mcp.config import parse_config
from praetor_mcp.gate import PolicyGate
from praetor_mcp.metrics import ProxyMetrics
from tests.test_hardening import _drive  # ASGI driver


# --- metrics ----------------------------------------------------------------
def test_metrics_render() -> None:
    m = ProxyMetrics()
    m.record_call("allow")
    m.record_call("allow")
    m.record_call("deny")
    m.record_upstream_error()
    m.record_auth_rejection()
    text = m.render_prometheus()
    assert 'praetor_mcp_calls_total{decision="allow"} 2' in text
    assert 'praetor_mcp_calls_total{decision="deny"} 1' in text
    assert "praetor_mcp_upstream_errors_total 1" in text
    assert "praetor_mcp_auth_rejections_total 1" in text


def _config() -> Any:
    return parse_config(
        {
            "agent": {"id": "a"},
            "upstreams": [{"name": "mock", "transport": "stdio", "command": ["x"]}],
        }
    )


def _gate(effect: Decision, tool: str = "mock__echo") -> PolicyGate:
    from praetor import PraetorClient

    pol = Policy(
        id="p", effect=effect,
        when=EqPredicate(path="tool.name", value=tool), reason="r",
        transform={} if effect is Decision.TRANSFORM else None,
    )
    return PolicyGate(PraetorClient(policies=[pol], default_agent_id="a"))


async def test_call_records_decision_metric() -> None:
    from praetor_mcp.server import PolicyBlocked, ProxyServer

    proxy = ProxyServer(_config(), gate=_gate(Decision.DENY))
    with pytest.raises(PolicyBlocked):
        await proxy.handle_call_tool("mock__echo", {})
    assert proxy.metrics._calls["deny"] == 1


# --- upstream reconnect + retry ---------------------------------------------
async def test_upstream_reconnect_retry(monkeypatch) -> None:
    from praetor_mcp.server import ProxyServer

    proxy = ProxyServer(_config(), gate=_gate(Decision.ALLOW))

    class _Failing:
        async def call_tool(self, tool: str, args: dict[str, Any]) -> Any:
            raise RuntimeError("upstream dropped")

    class _Healthy:
        async def call_tool(self, tool: str, args: dict[str, Any]) -> Any:
            return SimpleNamespace(content=["recovered"])

    proxy._routes["mock__echo"] = ("mock", "echo", _Failing())
    healthy = _Healthy()

    async def _fake_reconnect(name: str) -> Any:
        proxy._routes["mock__echo"] = ("mock", "echo", healthy)
        return healthy

    monkeypatch.setattr(proxy, "_reconnect", _fake_reconnect)
    result = await proxy.handle_call_tool("mock__echo", {})
    assert result == ["recovered"]
    assert proxy.metrics.upstream_errors == 1
    assert proxy.metrics._calls["allow"] == 1


async def test_reconnect_failure_propagates(monkeypatch) -> None:
    from praetor_mcp.server import ProxyServer

    proxy = ProxyServer(_config(), gate=_gate(Decision.ALLOW))

    class _Failing:
        async def call_tool(self, tool: str, args: dict[str, Any]) -> Any:
            raise RuntimeError("still down")

    proxy._routes["mock__echo"] = ("mock", "echo", _Failing())

    async def _reconnect_still_down(name: str) -> Any:
        return _Failing()

    monkeypatch.setattr(proxy, "_reconnect", _reconnect_still_down)
    with pytest.raises(RuntimeError, match="still down"):
        await proxy.handle_call_tool("mock__echo", {})
    assert proxy.metrics.upstream_errors == 1


# --- /metrics endpoint + auth rejection metric ------------------------------
async def test_metrics_endpoint() -> None:
    pytest.importorskip("mcp")
    from praetor_mcp.server import build_asgi_app

    app = build_asgi_app(_config())
    r = await _drive(app, headers=[], path="/metrics")
    assert r["status"] == 200
    assert b"praetor_mcp_calls_total" in r["body"]


async def test_auth_rejection_increments_metric() -> None:
    from praetor_mcp.auth import BearerAuthMiddleware

    metrics = ProxyMetrics()

    async def _inner(scope: Any, receive: Any, send: Any) -> None:  # pragma: no cover
        raise AssertionError("must not run")

    app = BearerAuthMiddleware(_inner, {"good": "a"}, metrics)
    await _drive(app, headers=[])
    assert metrics.auth_rejections == 1


# --- DNS-rebinding security settings ----------------------------------------
def test_build_asgi_app_with_allowed_hosts() -> None:
    pytest.importorskip("mcp")
    from praetor_mcp.server import build_asgi_app

    cfg = parse_config(
        {
            "agent": {"id": "a"},
            "upstreams": [{"name": "x", "transport": "stdio", "command": ["a"]}],
            "listen": {"allowed_hosts": ["mcp.example.com"], "allowed_origins": ["https://app.example.com"]},
        }
    )
    assert cfg.listen_allowed_hosts == ["mcp.example.com"]
    app = build_asgi_app(cfg)  # constructs TransportSecuritySettings without error
    paths = [getattr(r, "path", None) for r in app.routes]
    assert "/mcp" in paths and "/metrics" in paths


# --- tool-output DLP --------------------------------------------------------
async def test_tool_output_dlp_redacts(monkeypatch) -> None:
    from praetor_mcp.server import ProxyServer

    cfg = parse_config(
        {
            "agent": {"id": "a"},
            "upstreams": [{"name": "mock", "transport": "stdio", "command": ["x"]}],
            "enforcement": {"redact_tool_output": True},
        }
    )
    proxy = ProxyServer(cfg, gate=_gate(Decision.ALLOW))

    class _Session:
        async def call_tool(self, tool: str, args: dict[str, Any]) -> Any:
            block = SimpleNamespace(text="contact alice@example.com or key AKIA1234567890ABCD00")
            return SimpleNamespace(content=[block])

    proxy._routes["mock__echo"] = ("mock", "echo", _Session())
    content = await proxy.handle_call_tool("mock__echo", {})
    assert "alice@example.com" not in content[0].text
    assert proxy.metrics.output_redactions == 1


async def test_tool_output_dlp_off_by_default() -> None:
    from praetor_mcp.server import ProxyServer

    proxy = ProxyServer(_config(), gate=_gate(Decision.ALLOW))

    class _Session:
        async def call_tool(self, tool: str, args: dict[str, Any]) -> Any:
            return SimpleNamespace(content=[SimpleNamespace(text="alice@example.com")])

    proxy._routes["mock__echo"] = ("mock", "echo", _Session())
    content = await proxy.handle_call_tool("mock__echo", {})
    assert content[0].text == "alice@example.com"
    assert proxy.metrics.output_redactions == 0
