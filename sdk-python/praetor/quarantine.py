"""Client-side quarantine (EDR kill-switch) enforcement.

`QuarantineGuard` polls the control plane's `GET /quarantines/active` and
caches the result (TTL), so `PraetorClient.evaluate` can deny a quarantined
agent/session inline without a network round-trip on every call.

Availability posture: on a fetch error the last-known cache is retained; if
the control plane has never been reached, the guard fails open (allows) so a
control-plane outage doesn't halt every agent. Flip `fail_closed=True` for
environments that prefer to block on uncertainty.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable

import httpx

from praetor.transport import praetor_headers


class QuarantineGuard:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        org_slug: str | None = None,
        ttl_seconds: float = 30.0,
        fail_closed: bool = False,
        http_client: httpx.Client | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = base_url.rstrip("/") + "/quarantines/active"
        self._headers = praetor_headers(api_key, org_slug)
        self._ttl = ttl_seconds
        self._fail_closed = fail_closed
        self._client = http_client or httpx.Client(timeout=10.0)
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._fetched_at: float | None = None
        self._agent_reasons: dict[str, str] = {}
        self._session_reasons: dict[str, str] = {}

    def _refresh(self) -> None:
        resp = self._client.get(self._url, headers=self._headers)
        resp.raise_for_status()
        agent_reasons: dict[str, str] = {}
        session_reasons: dict[str, str] = {}
        for q in resp.json():
            reason = q.get("reason") or "quarantined"
            if q.get("agent_id"):
                agent_reasons[q["agent_id"]] = reason
            if q.get("session_id"):
                session_reasons[q["session_id"]] = reason
        with self._lock:
            self._agent_reasons = agent_reasons
            self._session_reasons = session_reasons
            self._fetched_at = self._monotonic()

    def _maybe_refresh(self) -> bool:
        """Refresh if the cache is stale. Returns True if a usable cache exists."""
        with self._lock:
            fetched_at = self._fetched_at
        if fetched_at is not None and (self._monotonic() - fetched_at) < self._ttl:
            return True
        with contextlib.suppress(Exception):
            self._refresh()
            return True
        # Refresh failed. A previously-populated cache is still usable.
        with self._lock:
            return self._fetched_at is not None

    def check(self, agent_id: str | None, session_id: str | None) -> str | None:
        """Return the quarantine reason if this entity is isolated, else None."""
        have_cache = self._maybe_refresh()
        if not have_cache:
            # Never reached the control plane. Fail open unless configured
            # otherwise.
            return "control plane unreachable" if self._fail_closed else None
        with self._lock:
            if agent_id and agent_id in self._agent_reasons:
                return self._agent_reasons[agent_id]
            if session_id and session_id in self._session_reasons:
                return self._session_reasons[session_id]
        return None


__all__ = ["QuarantineGuard"]
