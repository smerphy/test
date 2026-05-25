"""HTTP transport for the audit `RemoteShipper`.

Implements the `Transport` protocol against the control plane's
`POST /audit/events` endpoint. One event per request — the control
plane is idempotent on `(organization_id, hash)`, so the at-least-once
retry semantics in `RemoteShipper` are safe.
"""

from __future__ import annotations

import httpx

from praetor.audit import AuditEvent


class HttpTransport:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        org_slug: str | None = None,
        timeout_seconds: float = 10.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/audit/events"
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["X-API-Key"] = api_key
        if org_slug:
            self._headers["X-Org-Slug"] = org_slug
        self._client = http_client or httpx.Client(timeout=timeout_seconds)

    def ship(self, event: AuditEvent) -> None:
        # Send a single-event batch; the server accepts `list[AuditEvent]`.
        response = self._client.post(
            self._url,
            json=[event.model_dump(mode="json")],
            headers=self._headers,
        )
        response.raise_for_status()
        body = response.json()
        if body.get("rejected", 0) > 0:
            raise RuntimeError(
                f"control plane rejected event seq={event.seq}: "
                f"{body.get('errors', [])}"
            )


__all__ = ["HttpTransport"]
