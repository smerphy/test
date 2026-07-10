"""OTLP (OpenTelemetry) metrics → Ephorate MetricEvent translation.

The control-plane side of the OTel collector tier: a standard OpenTelemetry
Collector (or any OTLP exporter) can batch agent LLM telemetry and POST it here
as OTLP/HTTP JSON, so teams reuse the whole OTel pipeline (batching, retry,
backpressure, fan-out) instead of the bespoke SDK transport.

We map GenAI semantic-convention attributes on each metric data point to one
``MetricEventIn``. A data point describes a single model call:

    gen_ai.request.model / gen_ai.response.model  -> model
    gen_ai.usage.input_tokens                     -> input_tokens
    gen_ai.usage.output_tokens                    -> output_tokens
    ephorate.agent_id (or resource service.name)   -> agent_id
    ephorate.session_id                            -> session_id
    ephorate.duration_ms                           -> duration_ms
    ephorate.cost_usd                              -> cost_usd (else server-priced)
    ephorate.status                                -> status (default "success")
    timeUnixNano                                  -> timestamp

Only metrics named in ``_CALL_METRICS`` are consumed; everything else is
ignored, so a collector can multiplex Ephorate telemetry with unrelated metrics.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.schemas import MetricEventIn

# Metric names carrying a per-call data point (GenAI semconv + Ephorate's own).
_CALL_METRICS = frozenset(
    {"ephorate.llm.call", "gen_ai.client.operation.duration"}
)


def _attr_value(value: dict[str, Any]) -> Any:
    """Unwrap an OTLP AnyValue."""
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        return int(value["intValue"])
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "boolValue" in value:
        return bool(value["boolValue"])
    return None


def _attrs(attr_list: list[dict[str, Any]] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for a in attr_list or []:
        key = a.get("key")
        if key is not None:
            out[key] = _attr_value(a.get("value", {}))
    return out


def _ts(time_unix_nano: Any) -> datetime:
    try:
        return datetime.fromtimestamp(int(time_unix_nano) / 1e9, tz=UTC)
    except (TypeError, ValueError):
        return datetime.now(UTC)


def _int(a: dict[str, Any], key: str) -> int:
    try:
        return max(0, int(a.get(key, 0)))
    except (TypeError, ValueError):
        return 0


def parse_metrics(otlp: dict[str, Any]) -> list[MetricEventIn]:
    """Translate an OTLP/HTTP metrics export into MetricEvents. Malformed data
    points are skipped, not fatal (a collector must never be hard-failed)."""
    events: list[MetricEventIn] = []
    for rm in otlp.get("resourceMetrics", []) or []:
        res_attrs = _attrs(rm.get("resource", {}).get("attributes"))
        for sm in rm.get("scopeMetrics", []) or []:
            for metric in sm.get("metrics", []) or []:
                if metric.get("name") not in _CALL_METRICS:
                    continue
                container = metric.get("sum") or metric.get("gauge") or {}
                for dp in container.get("dataPoints", []) or []:
                    a = {**res_attrs, **_attrs(dp.get("attributes"))}
                    model = a.get("gen_ai.request.model") or a.get(
                        "gen_ai.response.model"
                    )
                    if not model:
                        continue
                    agent = (
                        a.get("ephorate.agent_id")
                        or res_attrs.get("service.name")
                        or "unknown"
                    )
                    cost = a.get("ephorate.cost_usd")
                    events.append(
                        MetricEventIn(
                            timestamp=_ts(dp.get("timeUnixNano")),
                            agent_id=str(agent),
                            session_id=a.get("ephorate.session_id"),
                            model=str(model),
                            duration_ms=_int(a, "ephorate.duration_ms"),
                            input_tokens=_int(a, "gen_ai.usage.input_tokens"),
                            output_tokens=_int(a, "gen_ai.usage.output_tokens"),
                            cost_usd=float(cost) if cost is not None else None,
                            status=str(a.get("ephorate.status", "success")),
                        )
                    )
    return events


__all__ = ["parse_metrics"]
