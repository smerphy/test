"""Claude API monitoring.

Wraps a caller's `anthropic.Anthropic` client (or any object that
exposes a Messages-API-shaped `messages.create`). For every call:

  - times it
  - extracts model, input / output / cache token counts, stop_reason,
    request_id from the response
  - computes cost via the bundled price book (override via env)
  - ships a `MetricEvent` to the configured control plane and/or
    captures it into a callback

Failures (rate-limit, API errors, transport errors) are also captured
as `MetricEvent`s with `status="error"` / `error_type=<class name>`,
then re-raised. The monitor never swallows the underlying error.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx

# Price book + cost computation are shared with the control plane via
# ephorate_engine.pricing (one price table, one EPHORATE_CLAUDE_PRICE_BOOK_JSON
# override read in one place — the SDK previously ignored that env var).
from ephorate_engine.pricing import compute_cost_usd

from ephorate.transport import ephorate_headers


@dataclass(frozen=True)
class MetricEvent:
    """One Claude API call worth of telemetry. Mirrors the control
    plane's ingestion shape; ship via `to_dict()`."""

    timestamp: datetime
    agent_id: str
    session_id: str | None
    model: str
    operation: str
    request_id: str | None
    duration_ms: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: float
    status: str
    stop_reason: str | None
    error_type: str | None
    tools_used: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "model": self.model,
            "operation": self.operation,
            "request_id": self.request_id,
            "duration_ms": self.duration_ms,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "cost_usd": self.cost_usd,
            "status": self.status,
            "stop_reason": self.stop_reason,
            "error_type": self.error_type,
            "tools_used": self.tools_used,
            "metadata": self.metadata,
        }


class MetricSink(Protocol):
    def record(self, event: MetricEvent) -> None: ...


class NullMetricSink:
    def record(self, event: MetricEvent) -> None:
        return None


class CallbackMetricSink:
    """Calls a user-provided function for each event. Useful for tests."""

    def __init__(self, fn: Callable[[MetricEvent], None]) -> None:
        self._fn = fn

    def record(self, event: MetricEvent) -> None:
        self._fn(event)


class ControlPlaneMetricSink:
    """Buffers events and POSTs batches to `<base_url>/metrics/events`.

    Buffering is bounded; on overflow we drop oldest (cost-of-business
    for monitoring data, in contrast to audit which is sacred).
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        org_slug: str | None = None,
        batch_size: int = 50,
        max_buffer: int = 10_000,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/metrics/events"
        self._headers = ephorate_headers(api_key, org_slug)
        self._client = http_client or httpx.Client(timeout=10.0)
        self._batch_size = batch_size
        self._max_buffer = max_buffer
        self._buffer: list[MetricEvent] = []
        # One monitor commonly wraps a client shared across threads, so
        # record()/flush() can run concurrently. Guard the buffer so a
        # batch isn't double-shipped (both threads swap the same list) or
        # an appended event lost between append and swap.
        self._lock = threading.Lock()

    def record(self, event: MetricEvent) -> None:
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) > self._max_buffer:
                # Drop oldest; monitoring data is best-effort.
                self._buffer = self._buffer[-self._max_buffer:]
            ready = len(self._buffer) >= self._batch_size
        if ready:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer
            self._buffer = []
        try:
            r = self._client.post(
                self._url,
                json=[e.to_dict() for e in batch],
                headers=self._headers,
            )
            r.raise_for_status()
        except Exception:
            # Re-queue on failure (caller can retry via a fresh call).
            with self._lock:
                self._buffer = batch + self._buffer


def _extract_usage(response: Any) -> dict[str, int]:
    """Pull token counts from a Messages-API response (typed object or dict)."""
    usage = getattr(response, "usage", None) or (
        response.get("usage") if isinstance(response, dict) else None
    )
    if usage is None:
        return {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}

    def _get(name: str) -> int:
        if isinstance(usage, dict):
            return int(usage.get(name, 0) or 0)
        return int(getattr(usage, name, 0) or 0)

    return {
        "input": _get("input_tokens"),
        "output": _get("output_tokens"),
        "cache_read": _get("cache_read_input_tokens"),
        "cache_write": _get("cache_creation_input_tokens"),
    }


def _extract_tools_used(response: Any) -> list[str]:
    content = getattr(response, "content", None) or (
        response.get("content") if isinstance(response, dict) else None
    )
    if not content:
        return []
    names: list[str] = []
    for block in content:
        block_type = block.get("type") if isinstance(block, dict) else getattr(block, "type", None)
        if block_type == "tool_use":
            name = block.get("name") if isinstance(block, dict) else getattr(block, "name", None)
            if isinstance(name, str):
                names.append(name)
    return names


def _extract_stop_reason(response: Any) -> str | None:
    sr = getattr(response, "stop_reason", None)
    if sr is None and isinstance(response, dict):
        sr = response.get("stop_reason")
    return sr if isinstance(sr, str) else None


def _extract_request_id(response: Any) -> str | None:
    rid = getattr(response, "_request_id", None) or getattr(response, "id", None)
    if rid is None and isinstance(response, dict):
        rid = response.get("id")
    return rid if isinstance(rid, str) else None


class AnthropicMonitor:
    """Wrap an `anthropic.Anthropic` (or compatible) client to capture
    Claude API metrics.

    Drop-in for the `messages.create` call path. Either inject the
    wrapped client directly, or use the `track()` context manager
    around an inline call.
    """

    def __init__(
        self,
        client: Any,
        *,
        agent_id: str,
        sink: MetricSink | None = None,
        session_id: str | None = None,
    ) -> None:
        self._client = client
        self._agent_id = agent_id
        self._sink = sink or NullMetricSink()
        self._session_id = session_id

    @property
    def messages(self) -> _MessagesProxy:
        return _MessagesProxy(self)

    @contextmanager
    def track(
        self,
        *,
        model: str,
        operation: str = "messages.create",
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Time a manual call and emit one metric event for it.

        Yields a mutable context dict; populate it with token counts /
        stop_reason if you compute them outside the auto-wrap path.
        """
        ctx: dict[str, Any] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "stop_reason": None,
            "request_id": None,
            "tools_used": [],
        }
        t0 = time.perf_counter()
        status = "success"
        error_type: str | None = None
        try:
            yield ctx
        except Exception as exc:
            status = "error"
            error_type = type(exc).__name__
            raise
        finally:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            self._sink.record(
                MetricEvent(
                    timestamp=datetime.now(UTC),
                    agent_id=self._agent_id,
                    session_id=session_id or self._session_id,
                    model=model,
                    operation=operation,
                    request_id=ctx.get("request_id"),
                    duration_ms=duration_ms,
                    input_tokens=int(ctx.get("input_tokens") or 0),
                    output_tokens=int(ctx.get("output_tokens") or 0),
                    cache_read_tokens=int(ctx.get("cache_read_tokens") or 0),
                    cache_write_tokens=int(ctx.get("cache_write_tokens") or 0),
                    cost_usd=compute_cost_usd(
                        model=model,
                        input_tokens=int(ctx.get("input_tokens") or 0),
                        output_tokens=int(ctx.get("output_tokens") or 0),
                        cache_read_tokens=int(ctx.get("cache_read_tokens") or 0),
                        cache_write_tokens=int(ctx.get("cache_write_tokens") or 0),
                    ),
                    status=status,
                    stop_reason=ctx.get("stop_reason"),
                    error_type=error_type,
                    tools_used=list(ctx.get("tools_used") or []),
                    metadata=dict(metadata or {}),
                )
            )

    def _record_response(
        self,
        response: Any,
        *,
        model: str,
        duration_ms: int,
        session_id: str | None,
        metadata: dict[str, Any] | None,
    ) -> None:
        usage = _extract_usage(response)
        cost = compute_cost_usd(
            model=model,
            input_tokens=usage["input"],
            output_tokens=usage["output"],
            cache_read_tokens=usage["cache_read"],
            cache_write_tokens=usage["cache_write"],
        )
        self._sink.record(
            MetricEvent(
                timestamp=datetime.now(UTC),
                agent_id=self._agent_id,
                session_id=session_id or self._session_id,
                model=model,
                operation="messages.create",
                request_id=_extract_request_id(response),
                duration_ms=duration_ms,
                input_tokens=usage["input"],
                output_tokens=usage["output"],
                cache_read_tokens=usage["cache_read"],
                cache_write_tokens=usage["cache_write"],
                cost_usd=cost,
                status="success",
                stop_reason=_extract_stop_reason(response),
                error_type=None,
                tools_used=_extract_tools_used(response),
                metadata=dict(metadata or {}),
            )
        )

    def _record_error(
        self,
        exc: BaseException,
        *,
        model: str,
        duration_ms: int,
        session_id: str | None,
        metadata: dict[str, Any] | None,
    ) -> None:
        self._sink.record(
            MetricEvent(
                timestamp=datetime.now(UTC),
                agent_id=self._agent_id,
                session_id=session_id or self._session_id,
                model=model,
                operation="messages.create",
                request_id=None,
                duration_ms=duration_ms,
                input_tokens=0,
                output_tokens=0,
                cache_read_tokens=0,
                cache_write_tokens=0,
                cost_usd=0.0,
                status="error",
                stop_reason=None,
                error_type=type(exc).__name__,
                tools_used=[],
                metadata=dict(metadata or {}),
            )
        )


class _MessagesProxy:
    """Mimics `anthropic.Anthropic().messages` for the `.create()` path."""

    def __init__(self, monitor: AnthropicMonitor) -> None:
        self._monitor = monitor

    def create(self, **kwargs: Any) -> Any:
        model = kwargs.get("model", "<unknown>")
        ephorate_session_id = kwargs.pop("ephorate_session_id", None)
        ephorate_metadata = kwargs.pop("ephorate_metadata", None)
        t0 = time.perf_counter()
        try:
            response = self._monitor._client.messages.create(**kwargs)
        except Exception as exc:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            self._monitor._record_error(
                exc,
                model=model,
                duration_ms=duration_ms,
                session_id=ephorate_session_id,
                metadata=ephorate_metadata,
            )
            raise
        duration_ms = int((time.perf_counter() - t0) * 1000)
        self._monitor._record_response(
            response,
            model=model,
            duration_ms=duration_ms,
            session_id=ephorate_session_id,
            metadata=ephorate_metadata,
        )
        return response


__all__ = [
    "AnthropicMonitor",
    "AsyncAnthropicMonitor",
    "CallbackMetricSink",
    "ControlPlaneMetricSink",
    "MetricEvent",
    "MetricSink",
    "NullMetricSink",
    "compute_cost_usd",
]


class _StreamProxy:
    """Wrap a sync streaming context manager from the Anthropic SDK.

    The Anthropic stream object exposes `.get_final_message()` once the
    stream is fully consumed; we use that to extract token / cost /
    stop_reason after the caller exits the `with` block.
    """

    def __init__(
        self,
        underlying_cm: Any,
        *,
        monitor: AnthropicMonitor,
        model: str,
        session_id: str | None,
        metadata: dict[str, Any] | None,
    ) -> None:
        self._cm = underlying_cm
        self._monitor = monitor
        self._model = model
        self._session_id = session_id
        self._metadata = metadata
        self._t0: float = 0.0
        self._stream: Any = None
        self._exc: BaseException | None = None

    def __enter__(self) -> Any:
        self._t0 = time.perf_counter()
        try:
            self._stream = self._cm.__enter__()
        except BaseException as exc:
            duration_ms = int((time.perf_counter() - self._t0) * 1000)
            self._monitor._record_error(
                exc,
                model=self._model,
                duration_ms=duration_ms,
                session_id=self._session_id,
                metadata=self._metadata,
            )
            raise
        return self._stream

    def __exit__(self, exc_type: Any, exc: BaseException | None, tb: Any) -> bool | None:
        self._exc = exc
        try:
            result: bool | None = self._cm.__exit__(exc_type, exc, tb)
        finally:
            duration_ms = int((time.perf_counter() - self._t0) * 1000)
            if self._exc is not None:
                self._monitor._record_error(
                    self._exc,
                    model=self._model,
                    duration_ms=duration_ms,
                    session_id=self._session_id,
                    metadata=self._metadata,
                )
            else:
                final = _safe_get_final_message(self._stream)
                self._monitor._record_response(
                    final or {},
                    model=self._model,
                    duration_ms=duration_ms,
                    session_id=self._session_id,
                    metadata=self._metadata,
                )
        return result


class _AsyncStreamProxy:
    """Async counterpart to `_StreamProxy`."""

    def __init__(
        self,
        underlying_cm: Any,
        *,
        monitor: AsyncAnthropicMonitor,
        model: str,
        session_id: str | None,
        metadata: dict[str, Any] | None,
    ) -> None:
        self._cm = underlying_cm
        self._monitor = monitor
        self._model = model
        self._session_id = session_id
        self._metadata = metadata
        self._t0: float = 0.0
        self._stream: Any = None

    async def __aenter__(self) -> Any:
        self._t0 = time.perf_counter()
        try:
            self._stream = await self._cm.__aenter__()
        except BaseException as exc:
            duration_ms = int((time.perf_counter() - self._t0) * 1000)
            self._monitor._record_error(
                exc,
                model=self._model,
                duration_ms=duration_ms,
                session_id=self._session_id,
                metadata=self._metadata,
            )
            raise
        return self._stream

    async def __aexit__(
        self, exc_type: Any, exc: BaseException | None, tb: Any
    ) -> bool | None:
        try:
            result: bool | None = await self._cm.__aexit__(exc_type, exc, tb)
        finally:
            duration_ms = int((time.perf_counter() - self._t0) * 1000)
            if exc is not None:
                self._monitor._record_error(
                    exc,
                    model=self._model,
                    duration_ms=duration_ms,
                    session_id=self._session_id,
                    metadata=self._metadata,
                )
            else:
                final = await _safe_aget_final_message(self._stream)
                self._monitor._record_response(
                    final or {},
                    model=self._model,
                    duration_ms=duration_ms,
                    session_id=self._session_id,
                    metadata=self._metadata,
                )
        return result


def _safe_get_final_message(stream: Any) -> Any:
    """`Stream.get_final_message()` is the official sync accessor on the
    Anthropic SDK. Tolerant fallback: `final_message` attribute, or the
    stream object itself if it already looks like a Message.
    """
    getter = getattr(stream, "get_final_message", None)
    if callable(getter):
        try:
            return getter()
        except Exception:
            return None
    return getattr(stream, "final_message", None) or stream


async def _safe_aget_final_message(stream: Any) -> Any:
    getter = getattr(stream, "get_final_message", None)
    if callable(getter):
        try:
            result = getter()
            if hasattr(result, "__await__"):
                return await result
            return result
        except Exception:
            return None
    return getattr(stream, "final_message", None) or stream


class _StreamableMessagesProxy(_MessagesProxy):
    """`messages.create` + `messages.stream` for the sync monitor."""

    def stream(self, **kwargs: Any) -> _StreamProxy:
        model = kwargs.get("model", "<unknown>")
        ephorate_session_id = kwargs.pop("ephorate_session_id", None)
        ephorate_metadata = kwargs.pop("ephorate_metadata", None)
        underlying = self._monitor._client.messages.stream(**kwargs)
        return _StreamProxy(
            underlying,
            monitor=self._monitor,
            model=model,
            session_id=ephorate_session_id,
            metadata=ephorate_metadata,
        )


# Re-bind the property on AnthropicMonitor to use the streamable variant.
AnthropicMonitor.messages = property(  # type: ignore[assignment]
    lambda self: _StreamableMessagesProxy(self),
)


class _AsyncMessagesProxy:
    """Async version of `_MessagesProxy`. Adds `stream(...)` support."""

    def __init__(self, monitor: AsyncAnthropicMonitor) -> None:
        self._monitor = monitor

    async def create(self, **kwargs: Any) -> Any:
        model = kwargs.get("model", "<unknown>")
        ephorate_session_id = kwargs.pop("ephorate_session_id", None)
        ephorate_metadata = kwargs.pop("ephorate_metadata", None)
        t0 = time.perf_counter()
        try:
            response = await self._monitor._client.messages.create(**kwargs)
        except Exception as exc:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            self._monitor._record_error(
                exc,
                model=model,
                duration_ms=duration_ms,
                session_id=ephorate_session_id,
                metadata=ephorate_metadata,
            )
            raise
        duration_ms = int((time.perf_counter() - t0) * 1000)
        self._monitor._record_response(
            response,
            model=model,
            duration_ms=duration_ms,
            session_id=ephorate_session_id,
            metadata=ephorate_metadata,
        )
        return response

    def stream(self, **kwargs: Any) -> _AsyncStreamProxy:
        model = kwargs.get("model", "<unknown>")
        ephorate_session_id = kwargs.pop("ephorate_session_id", None)
        ephorate_metadata = kwargs.pop("ephorate_metadata", None)
        underlying = self._monitor._client.messages.stream(**kwargs)
        return _AsyncStreamProxy(
            underlying,
            monitor=self._monitor,
            model=model,
            session_id=ephorate_session_id,
            metadata=ephorate_metadata,
        )


class AsyncAnthropicMonitor(AnthropicMonitor):
    """Async drop-in for `anthropic.AsyncAnthropic`.

    Same recording surface as `AnthropicMonitor`; the only difference
    is the `messages.create` / `messages.stream` access path uses
    `await` / `async with`.
    """

    @property
    def messages(self) -> _AsyncMessagesProxy:  # type: ignore[override]
        return _AsyncMessagesProxy(self)
