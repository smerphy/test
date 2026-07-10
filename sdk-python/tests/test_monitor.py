"""AnthropicMonitor: capture Claude API call metrics."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from ephorate import (
    AnthropicMonitor,
    CallbackMetricSink,
    ControlPlaneMetricSink,
    MetricEvent,
    NullMetricSink,
    compute_cost_usd,
)


def _mock_anthropic_client(response: Any) -> MagicMock:
    """Mimic the Anthropic SDK's `client.messages.create` surface."""
    client = MagicMock()
    client.messages.create.return_value = response
    return client


def _response(
    *,
    request_id: str = "msg_01abc",
    model: str = "claude-opus-4-7",
    input_tokens: int = 1000,
    output_tokens: int = 500,
    cache_read_input_tokens: int = 0,
    cache_creation_input_tokens: int = 0,
    stop_reason: str = "end_turn",
    content: list[dict] | None = None,
) -> dict:
    return {
        "id": request_id,
        "model": model,
        "content": content
        or [{"type": "text", "text": "hi"}],
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_input_tokens": cache_read_input_tokens,
            "cache_creation_input_tokens": cache_creation_input_tokens,
        },
    }


class TestCostBook:
    def test_compute_cost_known_model(self) -> None:
        cost = compute_cost_usd(
            model="claude-opus-4-7", input_tokens=1000, output_tokens=500
        )
        # 1000 * 15/1e6 + 500 * 75/1e6 = 0.015 + 0.0375 = 0.0525
        assert cost == pytest.approx(0.0525)

    def test_unknown_model_returns_zero(self) -> None:
        assert compute_cost_usd(model="claude-imaginary", input_tokens=1000) == 0.0

    def test_cache_tokens_included(self) -> None:
        cost = compute_cost_usd(
            model="claude-opus-4-7",
            input_tokens=0,
            output_tokens=0,
            cache_read_tokens=1_000_000,
            cache_write_tokens=1_000_000,
        )
        # 1M * 1.5/1M + 1M * 18.75/1M = 20.25
        assert cost == pytest.approx(20.25)


class TestAnthropicMonitorSuccessPath:
    def test_records_event_on_success(self) -> None:
        events: list[MetricEvent] = []
        sink = CallbackMetricSink(events.append)
        client = _mock_anthropic_client(_response())
        monitor = AnthropicMonitor(client, agent_id="research-bot", sink=sink)

        out = monitor.messages.create(
            model="claude-opus-4-7", messages=[{"role": "user", "content": "hi"}]
        )

        assert out["id"] == "msg_01abc"  # original response returned untouched
        assert len(events) == 1
        ev = events[0]
        assert ev.agent_id == "research-bot"
        assert ev.model == "claude-opus-4-7"
        assert ev.status == "success"
        assert ev.input_tokens == 1000
        assert ev.output_tokens == 500
        assert ev.stop_reason == "end_turn"
        assert ev.request_id == "msg_01abc"
        assert ev.cost_usd == pytest.approx(0.0525)
        assert ev.duration_ms >= 0

    def test_captures_tool_use_block_names(self) -> None:
        events: list[MetricEvent] = []
        sink = CallbackMetricSink(events.append)
        client = _mock_anthropic_client(
            _response(
                stop_reason="tool_use",
                content=[
                    {"type": "text", "text": "let me check"},
                    {"type": "tool_use", "id": "tu_1", "name": "http.get", "input": {}},
                    {"type": "tool_use", "id": "tu_2", "name": "fs.read", "input": {}},
                ],
            )
        )
        AnthropicMonitor(client, agent_id="a", sink=sink).messages.create(
            model="claude-opus-4-7", messages=[]
        )
        assert events[0].tools_used == ["http.get", "fs.read"]
        assert events[0].stop_reason == "tool_use"

    def test_session_id_threaded_via_ephorate_kwarg(self) -> None:
        events: list[MetricEvent] = []
        sink = CallbackMetricSink(events.append)
        client = _mock_anthropic_client(_response())
        AnthropicMonitor(
            client, agent_id="a", sink=sink
        ).messages.create(
            model="claude-opus-4-7",
            messages=[],
            ephorate_session_id="sess-77",
            ephorate_metadata={"trace_id": "abc"},
        )
        assert events[0].session_id == "sess-77"
        assert events[0].metadata == {"trace_id": "abc"}
        # ephorate-* kwargs are scrubbed before reaching the SDK call.
        forwarded = client.messages.create.call_args.kwargs
        assert "ephorate_session_id" not in forwarded
        assert "ephorate_metadata" not in forwarded


class TestAnthropicMonitorErrorPath:
    def test_records_error_and_reraises(self) -> None:
        events: list[MetricEvent] = []
        sink = CallbackMetricSink(events.append)
        client = _mock_anthropic_client(None)
        client.messages.create.side_effect = RuntimeError("api blew up")
        monitor = AnthropicMonitor(client, agent_id="a", sink=sink)

        with pytest.raises(RuntimeError, match="api blew up"):
            monitor.messages.create(model="claude-opus-4-7", messages=[])

        assert len(events) == 1
        ev = events[0]
        assert ev.status == "error"
        assert ev.error_type == "RuntimeError"
        assert ev.cost_usd == 0.0
        assert ev.input_tokens == 0


class TestTrackContextManager:
    def test_track_records_supplied_metrics(self) -> None:
        events: list[MetricEvent] = []
        monitor = AnthropicMonitor(
            MagicMock(),
            agent_id="a",
            sink=CallbackMetricSink(events.append),
        )
        with monitor.track(model="claude-haiku-4-5") as ctx:
            ctx["input_tokens"] = 100
            ctx["output_tokens"] = 50
            ctx["stop_reason"] = "end_turn"
        assert len(events) == 1
        assert events[0].input_tokens == 100
        assert events[0].status == "success"

    def test_track_captures_exception(self) -> None:
        events: list[MetricEvent] = []
        monitor = AnthropicMonitor(
            MagicMock(),
            agent_id="a",
            sink=CallbackMetricSink(events.append),
        )
        with pytest.raises(ValueError), monitor.track(model="claude-opus-4-7"):
            raise ValueError("boom")
        assert events[0].status == "error"
        assert events[0].error_type == "ValueError"


class TestControlPlaneSink:
    @respx.mock
    def test_flushes_at_batch_size(self) -> None:
        route = respx.post("https://cp/metrics/events").mock(
            return_value=httpx.Response(202, json={"accepted": 3, "rejected": 0, "errors": []})
        )
        sink = ControlPlaneMetricSink(
            "https://cp", api_key="k", org_slug="acme", batch_size=3
        )
        for _ in range(3):
            sink.record(_event())
        # batch reached → flush happens automatically
        assert route.call_count == 1
        # API key + org slug propagated to request headers
        request = route.calls.last.request
        assert request.headers["X-API-Key"] == "k"
        assert request.headers["X-Org-Slug"] == "acme"

    @respx.mock
    def test_manual_flush(self) -> None:
        route = respx.post("https://cp/metrics/events").mock(
            return_value=httpx.Response(202, json={"accepted": 1, "rejected": 0, "errors": []})
        )
        sink = ControlPlaneMetricSink("https://cp", batch_size=100)
        sink.record(_event())
        assert route.call_count == 0
        sink.flush()
        assert route.call_count == 1

    @respx.mock
    def test_network_failure_re_queues(self) -> None:
        respx.post("https://cp/metrics/events").mock(return_value=httpx.Response(500))
        sink = ControlPlaneMetricSink("https://cp", batch_size=2)
        sink.record(_event())
        sink.record(_event())
        # Network failed → events should have been re-queued.
        assert len(sink._buffer) == 2


def _event() -> MetricEvent:
    from datetime import UTC, datetime

    return MetricEvent(
        timestamp=datetime.now(UTC),
        agent_id="a",
        session_id="s",
        model="claude-opus-4-7",
        operation="messages.create",
        request_id="r",
        duration_ms=10,
        input_tokens=1,
        output_tokens=1,
        cache_read_tokens=0,
        cache_write_tokens=0,
        cost_usd=0.0,
        status="success",
        stop_reason="end_turn",
        error_type=None,
        tools_used=[],
    )


class TestNullSink:
    def test_drops_events(self) -> None:
        NullMetricSink().record(_event())
