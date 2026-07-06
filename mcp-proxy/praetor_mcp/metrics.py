"""In-process proxy metrics, exposed as Prometheus text at ``/metrics``.

Operational counters for the proxy itself (distinct from the audit chain, which
goes to the control plane): tool calls by gate decision, upstream failures, and
rejected unauthenticated requests. Scrape ``GET /metrics``.
"""

from __future__ import annotations

from collections import Counter

_DECISIONS = ("allow", "transform", "deny", "require_approval")


class ProxyMetrics:
    def __init__(self) -> None:
        self._calls: Counter[str] = Counter()
        self.upstream_errors = 0
        self.auth_rejections = 0
        self.output_redactions = 0

    def record_call(self, decision: str) -> None:
        self._calls[decision] += 1

    def record_upstream_error(self) -> None:
        self.upstream_errors += 1

    def record_auth_rejection(self) -> None:
        self.auth_rejections += 1

    def render_prometheus(self) -> str:
        lines = [
            "# HELP praetor_mcp_calls_total Tool calls by gate decision.",
            "# TYPE praetor_mcp_calls_total counter",
        ]
        lines += [
            f'praetor_mcp_calls_total{{decision="{d}"}} {self._calls.get(d, 0)}'
            for d in _DECISIONS
        ]
        lines += [
            "# HELP praetor_mcp_upstream_errors_total Upstream call failures.",
            "# TYPE praetor_mcp_upstream_errors_total counter",
            f"praetor_mcp_upstream_errors_total {self.upstream_errors}",
            "# HELP praetor_mcp_auth_rejections_total Rejected unauthenticated requests.",
            "# TYPE praetor_mcp_auth_rejections_total counter",
            f"praetor_mcp_auth_rejections_total {self.auth_rejections}",
            "# HELP praetor_mcp_output_redactions_total Tool-output blocks redacted (DLP).",
            "# TYPE praetor_mcp_output_redactions_total counter",
            f"praetor_mcp_output_redactions_total {self.output_redactions}",
        ]
        return "\n".join(lines) + "\n"


__all__ = ["ProxyMetrics"]
