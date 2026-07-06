"""Per-tenant token-bucket rate limiting.

A FastAPI dependency (`rate_limit(bucket)`) throttles requests per
(organization, bucket) so one noisy or abusive tenant can't exhaust the
control plane or run up another tenant's cost. Buckets separate cheap,
high-volume ingestion from expensive AI calls.

The default store is in-process (per-worker). It is correct and dependency-
free for single-node / low-node deployments; for a large multi-worker fleet,
back it with Redis (the `RateLimiter` interface is the seam) so limits are
global. Time is `time.monotonic()`, so it is immune to wall-clock changes.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from fastapi import Depends, HTTPException, status

from app.auth import Principal, current_principal
from app.settings import Settings, get_settings

_INGEST = "ingest"
_AI = "ai"
_DEFAULT = "default"


class RateLimiter:
    """In-process token bucket keyed by (org_id, bucket)."""

    def __init__(self) -> None:
        self._state: dict[tuple[str, str], tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(
        self, org_id: str, bucket: str, capacity: float, refill_per_sec: float
    ) -> float | None:
        """Consume one token. Returns None if allowed, else the retry-after
        seconds."""
        now = time.monotonic()
        key = (org_id, bucket)
        with self._lock:
            tokens, last = self._state.get(key, (capacity, now))
            tokens = min(capacity, tokens + (now - last) * refill_per_sec)
            if tokens < 1.0:
                self._state[key] = (tokens, now)
                deficit = 1.0 - tokens
                return deficit / refill_per_sec if refill_per_sec > 0 else 60.0
            self._state[key] = (tokens - 1.0, now)
            return None

    def reset(self) -> None:
        with self._lock:
            self._state.clear()


_limiter = RateLimiter()


def reset_limiter() -> None:
    """Clear all buckets (tests)."""
    _limiter.reset()


def _capacity(bucket: str, settings: Settings) -> int:
    if bucket == _INGEST:
        return settings.rate_limit_ingest_per_min
    if bucket == _AI:
        return settings.rate_limit_ai_per_min
    return settings.rate_limit_default_per_min


def rate_limit(bucket: str) -> Callable[..., None]:
    """Dependency factory: 429 when the caller's org exceeds `bucket`'s rate."""

    def dependency(
        principal: Principal = Depends(current_principal),
        settings: Settings = Depends(get_settings),
    ) -> None:
        if not settings.rate_limit_enabled:
            return
        capacity = _capacity(bucket, settings)
        retry = _limiter.check(
            principal.org.id, bucket, float(capacity), capacity / 60.0
        )
        if retry is not None:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"rate limit exceeded for '{bucket}' bucket",
                headers={"Retry-After": str(int(retry) + 1)},
            )

    return dependency


__all__ = ["RateLimiter", "rate_limit", "reset_limiter"]
