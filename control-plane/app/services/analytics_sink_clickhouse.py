"""ClickHouse backend for the analytics consumer.

The columnar store for full-history aggregation (spend/usage/decision-rate
rollups over billions of rows) that Postgres shouldn't carry. Selected with
``EPHORATE_ANALYTICS_SINK=clickhouse`` + ``EPHORATE_CLICKHOUSE_DSN``.

``clickhouse-connect`` is an optional dependency, imported lazily so the
control plane runs (and CI passes) without it. Records are inserted as raw JSON
into per-topic tables (e.g. ``ephorate_analytics_audit``) with a small set of
materialized columns for fast grouping; the table DDL is managed out of band by
the deployment. Not exercised in CI (no ClickHouse server).
"""

from __future__ import annotations

from typing import Any

Record = dict[str, Any]


class ClickHouseAnalyticsSink:
    """AnalyticsSink over ClickHouse. Requires clickhouse-connect + a server."""

    def __init__(self) -> None:  # pragma: no cover - needs a server
        from app.settings import get_settings

        dsn = get_settings().clickhouse_dsn
        if not dsn:
            raise RuntimeError(
                "analytics_sink=clickhouse requires EPHORATE_CLICKHOUSE_DSN"
            )
        self._dsn = dsn
        self._client: Any = None

    def _get_client(self) -> Any:  # pragma: no cover - needs a server
        if self._client is None:
            import clickhouse_connect

            self._client = clickhouse_connect.get_client(dsn=self._dsn)
        return self._client

    def write(
        self, topic: str, org_id: str, records: list[Record]
    ) -> int:  # pragma: no cover - needs a server
        import json

        if not records:
            return 0
        client = self._get_client()
        table = f"ephorate_analytics_{topic}"
        rows = [(org_id, json.dumps(rec)) for rec in records]
        client.insert(table, rows, column_names=["organization_id", "payload"])
        return len(records)


__all__ = ["ClickHouseAnalyticsSink"]
