"""Praetor MCP proxy — policy-gate, audit, and control MCP tool calls.

The policy core (`gate`, `config`) has no MCP runtime dependency and is fully
tested; the transport wiring (`server`) imports the optional `mcp` package
lazily. Install the runtime with `pip install praetor-mcp[runtime]`.
"""

from __future__ import annotations

from praetor_mcp.config import (
    EnforcementConfig,
    ProxyConfig,
    UpstreamConfig,
    build_client,
    load_config,
    parse_config,
)
from praetor_mcp.gate import GateResult, PolicyGate

__all__ = [
    "EnforcementConfig",
    "GateResult",
    "PolicyGate",
    "ProxyConfig",
    "UpstreamConfig",
    "build_client",
    "load_config",
    "parse_config",
]

__version__ = "0.1.0"
