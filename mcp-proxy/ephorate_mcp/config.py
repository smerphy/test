"""Proxy configuration (ephorate-mcp.yaml) and EphorateClient construction."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from ephorate import EphorateClient
from ephorate_engine.parser import parse_bundle_file

_VALID_TRANSPORTS = ("stdio", "streamable-http")


@dataclass
class UpstreamConfig:
    name: str
    transport: str
    command: list[str] = field(default_factory=list)  # stdio
    url: str | None = None  # streamable-http
    env: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if self.transport not in _VALID_TRANSPORTS:
            raise ValueError(
                f"upstream {self.name!r}: transport must be one of {_VALID_TRANSPORTS}"
            )
        if self.transport == "stdio" and not self.command:
            raise ValueError(f"upstream {self.name!r}: stdio requires a command")
        if self.transport == "streamable-http" and not self.url:
            raise ValueError(f"upstream {self.name!r}: streamable-http requires a url")


@dataclass
class EnforcementConfig:
    on_error: str = "deny"  # fail-closed by default (it's a security control)
    approval_timeout_seconds: int = 300
    hide_denied_tools: bool = True
    # Tool-output DLP: redact PII/secrets in tools/call *results* before the
    # agent sees them (emails, tokens, keys, cards). Off by default.
    redact_tool_output: bool = False


@dataclass
class ProxyConfig:
    upstreams: list[UpstreamConfig]
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)
    control_plane_url: str | None = None
    api_key: str | None = None
    org_slug: str | None = None
    bundle_path: str | None = None
    agent_id: str | None = None
    audit_log_path: str = "ephorate-mcp-audit.jsonl"
    listen_transport: str = "streamable-http"
    listen_bind: str | None = "127.0.0.1:8090"
    listen_path: str = "/mcp"
    # Downstream (incoming agent) auth for the HTTP listen: bearer token ->
    # agent_id. When set, unauthenticated requests are rejected and each call
    # is attributed to the token's agent. Empty = no auth (stdio sidecar / dev).
    listen_auth_tokens: dict[str, str] = field(default_factory=dict)
    # DNS-rebinding protection for the HTTP listen: allowed Host / Origin
    # values. When set, the MCP session manager rejects requests with other
    # Host/Origin headers. Empty = protection off (localhost/dev).
    listen_allowed_hosts: list[str] = field(default_factory=list)
    listen_allowed_origins: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if not self.upstreams:
            raise ValueError("at least one upstream must be configured")
        for u in self.upstreams:
            u.validate()
        if self.enforcement.on_error not in ("deny", "allow"):
            raise ValueError("enforcement.on_error must be 'deny' or 'allow'")
        if self.listen_transport not in _VALID_TRANSPORTS:
            raise ValueError(f"listen.transport must be one of {_VALID_TRANSPORTS}")


def parse_config(data: dict[str, Any]) -> ProxyConfig:
    """Build a ProxyConfig from a parsed YAML/dict document."""
    cp = data.get("control_plane", {}) or {}
    policy = data.get("policy", {}) or {}
    agent = data.get("agent", {}) or {}
    enf = data.get("enforcement", {}) or {}
    listen = data.get("listen", {}) or {}
    upstreams = [
        UpstreamConfig(
            name=u["name"],
            transport=u.get("transport", "stdio"),
            command=list(u.get("command", [])),
            url=u.get("url"),
            env=dict(u.get("env", {})),
        )
        for u in data.get("upstreams", []) or []
    ]
    config = ProxyConfig(
        upstreams=upstreams,
        enforcement=EnforcementConfig(
            on_error=enf.get("on_error", "deny"),
            approval_timeout_seconds=int(enf.get("approval_timeout_seconds", 300)),
            hide_denied_tools=bool(enf.get("hide_denied_tools", True)),
            redact_tool_output=bool(enf.get("redact_tool_output", False)),
        ),
        control_plane_url=cp.get("url"),
        api_key=cp.get("api_key"),
        org_slug=cp.get("org_slug"),
        bundle_path=policy.get("bundle_path"),
        agent_id=agent.get("id"),
        audit_log_path=data.get("audit_log_path", "ephorate-mcp-audit.jsonl"),
        listen_transport=listen.get("transport", "streamable-http"),
        listen_bind=listen.get("bind", "127.0.0.1:8090"),
        listen_path=listen.get("path", "/mcp"),
        listen_auth_tokens=dict(listen.get("auth_tokens", {})),
        listen_allowed_hosts=list(listen.get("allowed_hosts", [])),
        listen_allowed_origins=list(listen.get("allowed_origins", [])),
    )
    config.validate()
    return config


def load_config(path: Path | str) -> ProxyConfig:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # Expand ${VAR} / $VAR from the environment so secrets (API keys, upstream
    # tokens) live in the process env, not in the YAML on disk. Undefined vars
    # are left intact.
    data = yaml.safe_load(os.path.expandvars(text)) or {}
    if not isinstance(data, dict):
        raise ValueError("config root must be a mapping")
    return parse_config(data)


def build_client(config: ProxyConfig) -> EphorateClient:
    """Construct the EphorateClient the gate drives (engine + audit + shipping +
    approval + quarantine), from config."""
    policies = (
        parse_bundle_file(config.bundle_path) if config.bundle_path else []
    )
    return EphorateClient(
        policies=policies,
        control_plane_url=config.control_plane_url,
        api_key=config.api_key,
        org_slug=config.org_slug,
        audit_log_path=config.audit_log_path,
        default_agent_id=config.agent_id,
    )


__all__ = [
    "EnforcementConfig",
    "ProxyConfig",
    "UpstreamConfig",
    "build_client",
    "load_config",
    "parse_config",
]
