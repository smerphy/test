"""OTLP metrics receiver (OTel collector tier)."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import MetricEvent
from app.services.otlp import parse_metrics


def _otlp(model: str = "claude-sonnet-4-6", agent: str = "agent-1") -> dict[str, Any]:
    return {
        "resourceMetrics": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": agent}}
                    ]
                },
                "scopeMetrics": [
                    {
                        "metrics": [
                            # Ignored — not a call metric.
                            {"name": "process.cpu.time", "sum": {"dataPoints": []}},
                            {
                                "name": "ephorate.llm.call",
                                "sum": {
                                    "dataPoints": [
                                        {
                                            "timeUnixNano": "1800000000000000000",
                                            "asInt": "1",
                                            "attributes": [
                                                {
                                                    "key": "gen_ai.request.model",
                                                    "value": {"stringValue": model},
                                                },
                                                {
                                                    "key": "gen_ai.usage.input_tokens",
                                                    "value": {"intValue": "100"},
                                                },
                                                {
                                                    "key": "gen_ai.usage.output_tokens",
                                                    "value": {"intValue": "40"},
                                                },
                                                {
                                                    "key": "ephorate.duration_ms",
                                                    "value": {"intValue": "250"},
                                                },
                                                {
                                                    "key": "ephorate.cost_usd",
                                                    "value": {"doubleValue": 0.01},
                                                },
                                            ],
                                        }
                                    ]
                                },
                            },
                        ]
                    }
                ],
            }
        ]
    }


def test_parse_metrics_maps_datapoints() -> None:
    events = parse_metrics(_otlp())
    assert len(events) == 1
    ev = events[0]
    assert ev.model == "claude-sonnet-4-6"
    assert ev.agent_id == "agent-1"  # from resource service.name
    assert (ev.input_tokens, ev.output_tokens) == (100, 40)
    assert ev.duration_ms == 250
    assert ev.cost_usd == 0.01


def test_parse_metrics_ignores_unknown_and_modelless() -> None:
    assert parse_metrics({}) == []
    assert parse_metrics({"resourceMetrics": []}) == []
    # A call metric with no model attribute is skipped.
    bad = {
        "resourceMetrics": [
            {
                "scopeMetrics": [
                    {
                        "metrics": [
                            {
                                "name": "ephorate.llm.call",
                                "gauge": {"dataPoints": [{"attributes": []}]},
                            }
                        ]
                    }
                ]
            }
        ]
    }
    assert parse_metrics(bad) == []


def test_otlp_endpoint_ingests(client: TestClient, session: Session) -> None:
    r = client.post("/otlp/v1/metrics", json=_otlp())
    assert r.status_code == 200
    assert r.json() == {"accepted": 1, "rejected": 0}
    row = session.execute(select(MetricEvent)).scalar_one()
    assert row.model == "claude-sonnet-4-6"
    assert row.cost_usd == 0.01


def test_otlp_endpoint_empty(client: TestClient) -> None:
    r = client.post("/otlp/v1/metrics", json={"resourceMetrics": []})
    assert r.status_code == 200 and r.json() == {"accepted": 0, "rejected": 0}
