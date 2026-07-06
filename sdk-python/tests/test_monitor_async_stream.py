"""Async + streaming coverage for the monitor."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from praetor import (
    AnthropicMonitor,
    AsyncAnthropicMonitor,
    CallbackMetricSink,
    MetricEvent,
)


def _response(
    *,
    request_id: str = "msg_01",
    model: str = "claude-opus-4-7",
    input_tokens: int = 200,
    output_tokens: int = 100,
    stop_reason: str = "end_turn",
) -> dict[str, Any]:
    return {
        "id": request_id,
        "model": model,
        "content": [{"type": "text", "text": "ok"}],
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        },
    }


# --------------------------------------------------------------------- async


@pytest.mark.asyncio
async def test_async_monitor_records_success() -> None:
    events: list[MetricEvent] = []
    sink = CallbackMetricSink(events.append)
    client = MagicMock()
    client.messages.create = AsyncMock(return_value=_response())

    monitor = AsyncAnthropicMonitor(client, agent_id="agent-async", sink=sink)
    out = await monitor.messages.create(
        model="claude-opus-4-7", messages=[{"role": "user", "content": "hi"}]
    )
    assert out["id"] == "msg_01"
    assert len(events) == 1
    assert events[0].agent_id == "agent-async"
    assert events[0].status == "success"
    assert events[0].input_tokens == 200
    assert events[0].cost_usd > 0


@pytest.mark.asyncio
async def test_async_monitor_records_error_and_reraises() -> None:
    events: list[MetricEvent] = []
    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=RuntimeError("rate limited"))

    monitor = AsyncAnthropicMonitor(
        client, agent_id="a", sink=CallbackMetricSink(events.append)
    )
    with pytest.raises(RuntimeError, match="rate limited"):
        await monitor.messages.create(model="claude-opus-4-7", messages=[])
    assert events[0].status == "error"
    assert events[0].error_type == "RuntimeError"


@pytest.mark.asyncio
async def test_async_praetor_kwargs_scrubbed() -> None:
    events: list[MetricEvent] = []
    client = MagicMock()
    client.messages.create = AsyncMock(return_value=_response())
    monitor = AsyncAnthropicMonitor(
        client, agent_id="a", sink=CallbackMetricSink(events.append)
    )
    await monitor.messages.create(
        model="claude-opus-4-7",
        messages=[],
        praetor_session_id="sess-77",
        praetor_metadata={"trace_id": "t"},
    )
    assert events[0].session_id == "sess-77"
    forwarded = client.messages.create.call_args.kwargs
    assert "praetor_session_id" not in forwarded
    assert "praetor_metadata" not in forwarded


# --------------------------------------------------------------- streaming sync


class _FakeSyncStream:
    """Mimics the shape the SDK exposes via `with client.messages.stream(...) as s:`."""

    def __init__(self, final: dict[str, Any]) -> None:
        self._final = final

    def get_final_message(self) -> dict[str, Any]:
        return self._final


class _FakeSyncStreamCM:
    def __init__(self, final: dict[str, Any], *, raise_in: bool = False) -> None:
        self._final = final
        self._raise_in = raise_in

    def __enter__(self) -> _FakeSyncStream:
        if self._raise_in:
            raise RuntimeError("connect failed")
        return _FakeSyncStream(self._final)

    def __exit__(self, *args: Any) -> bool | None:
        return None


def test_streaming_records_final_usage() -> None:
    events: list[MetricEvent] = []
    client = MagicMock()
    client.messages.stream.return_value = _FakeSyncStreamCM(
        _response(input_tokens=500, output_tokens=250)
    )
    monitor = AnthropicMonitor(
        client, agent_id="a", sink=CallbackMetricSink(events.append)
    )
    with monitor.messages.stream(model="claude-opus-4-7", messages=[]) as s:
        # Caller would normally iterate `s.text_stream` etc. We just
        # check the proxy yielded the underlying stream object.
        assert s.get_final_message()["id"] == "msg_01"
    assert len(events) == 1
    ev = events[0]
    assert ev.status == "success"
    assert ev.input_tokens == 500
    assert ev.output_tokens == 250
    assert ev.cost_usd > 0


def test_streaming_records_error_on_enter() -> None:
    events: list[MetricEvent] = []
    client = MagicMock()
    client.messages.stream.return_value = _FakeSyncStreamCM(
        _response(), raise_in=True
    )
    monitor = AnthropicMonitor(
        client, agent_id="a", sink=CallbackMetricSink(events.append)
    )
    with (
        pytest.raises(RuntimeError, match="connect failed"),
        monitor.messages.stream(model="claude-opus-4-7", messages=[]),
    ):
        pass
    assert events[0].status == "error"
    assert events[0].error_type == "RuntimeError"


# -------------------------------------------------------------- streaming async


class _FakeAsyncStream:
    def __init__(self, final: dict[str, Any]) -> None:
        self._final = final

    def get_final_message(self) -> dict[str, Any]:
        return self._final


class _FakeAsyncStreamCM:
    def __init__(self, final: dict[str, Any]) -> None:
        self._final = final

    async def __aenter__(self) -> _FakeAsyncStream:
        return _FakeAsyncStream(self._final)

    async def __aexit__(self, *args: Any) -> bool | None:
        return None


@pytest.mark.asyncio
async def test_async_streaming_records_final_usage() -> None:
    events: list[MetricEvent] = []
    client = MagicMock()
    client.messages.stream.return_value = _FakeAsyncStreamCM(
        _response(input_tokens=400, output_tokens=80)
    )
    monitor = AsyncAnthropicMonitor(
        client, agent_id="a", sink=CallbackMetricSink(events.append)
    )
    async with monitor.messages.stream(model="claude-opus-4-7", messages=[]) as s:
        assert s.get_final_message()["id"] == "msg_01"
    assert len(events) == 1
    assert events[0].input_tokens == 400
    assert events[0].output_tokens == 80
    assert events[0].status == "success"
