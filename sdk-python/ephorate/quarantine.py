"""Client-side quarantine (EDR kill-switch) enforcement.

`QuarantineGuard` polls the control plane's authoritative
`GET /quarantines/check?agent_id=...&session_id=...` and caches each verdict
per (agent, session) with a TTL, so `EphorateClient.evaluate` can deny inline
without a network round-trip on every call.

Why `/quarantines/check` and not `/quarantines/active`: `/check` is the only
surface that composes ALL three isolation controls — the global kill-switch
(`Organization.halt_all`, minus break-glass), hard spend enforcement
(over-budget org / over-quota agent), and per-entity quarantines. `/active`
lists only per-entity quarantine rows, so an SDK polling it would leave the
kill-switch and spend cap completely unenforced inline.

Availability posture: on a fetch error the last-known verdict for that entity
is retained; if the control plane has never been reached for it, the guard
fails open (allows) so a control-plane outage doesn't halt every agent. Flip
`fail_closed=True` for environments that prefer to block on uncertainty.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

import httpx

from ephorate.transport import ephorate_headers

_Key = tuple[str | None, str | None]


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
        self._url = base_url.rstrip("/") + "/quarantines/check"
        self._headers = ephorate_headers(api_key, org_slug)
        self._ttl = ttl_seconds
        self._fail_closed = fail_closed
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(timeout=10.0)
        self._monotonic = monotonic
        self._lock = threading.Lock()
        # (agent_id, session_id) -> (fetched_at, reason_or_None)
        self._cache: dict[_Key, tuple[float, str | None]] = {}

    def _fetch(self, agent_id: str | None, session_id: str | None) -> str | None:
        """Ask the control plane whether this entity is isolated. Returns the
        reason string when quarantined, else None. Raises on transport error."""
        params: dict[str, str] = {}
        if agent_id:
            params["agent_id"] = agent_id
        if session_id:
            params["session_id"] = session_id
        resp = self._client.get(self._url, headers=self._headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        if data.get("quarantined"):
            return data.get("reason") or "quarantined"
        return None

    def check(self, agent_id: str | None, session_id: str | None) -> str | None:
        """Return the quarantine reason if this entity is isolated, else None."""
        key: _Key = (agent_id, session_id)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None and (self._monotonic() - cached[0]) < self._ttl:
            return cached[1]
        try:
            reason = self._fetch(agent_id, session_id)
        except Exception:
            # Refresh failed. Reuse the last-known verdict for this entity if we
            # have one; otherwise fail open (unless configured closed).
            if cached is not None:
                return cached[1]
            return "control plane unreachable" if self._fail_closed else None
        with self._lock:
            self._cache[key] = (self._monotonic(), reason)
        return reason

    def close(self) -> None:
        # Only close a client we created; a caller-injected one is theirs.
        if self._owns_client:
            self._client.close()


__all__ = ["QuarantineGuard"]
