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
from praetor_mcp.identity import Identity, current_identity, set_identity
from praetor_mcp.metrics import ProxyMetrics

__all__ = [
    "EnforcementConfig",
    "GateResult",
    "Identity",
    "PolicyGate",
    "ProxyConfig",
    "ProxyMetrics",
    "UpstreamConfig",
    "build_client",
    "current_identity",
    "load_config",
    "parse_config",
    "set_identity",
]

__version__ = "0.1.0"
