"""Columnar/analytics sink for the analytics consumer group.

The analytics consumer drains the log and writes each record here — a store
optimized for aggregation over the full history, separate from the hot
Postgres store that serves point/analyst queries. Backends:

* ``none``       — no-op (default; analytics tier disabled).
* ``ndjson``     — reuse the partitioned NDJSON cold archive (object-store
                   friendly, queryable by DuckDB/Athena/BigQuery).
* ``clickhouse`` — insert into ClickHouse (see ``analytics_sink_clickhouse``).

Selected by ``PRAETOR_ANALYTICS_SINK``. Kept behind a tiny protocol so the
consumer never knows which backend is live.
"""

from __future__ import annotations

from typing import Any, Protocol

from app.services.event_store import archive_events

Record = dict[str, Any]


class AnalyticsSink(Protocol):
    def write(self, topic: str, org_id: str, records: list[Record]) -> int:
        """Persist records for one (topic, org). Returns the number written."""
        ...


class NullAnalyticsSink:
    def write(self, topic: str, org_id: str, records: list[Record]) -> int:
        return 0


class NdjsonAnalyticsSink:
    """Write to the partitioned NDJSON archive under an analytics namespace."""

    def write(self, topic: str, org_id: str, records: list[Record]) -> int:
        return archive_events(f"analytics_{topic}", org_id, records)


_SINK: AnalyticsSink | None = None


def _build_sink() -> AnalyticsSink:
    from app.settings import get_settings

    choice = get_settings().analytics_sink
    if choice == "ndjson":
        return NdjsonAnalyticsSink()
    if choice == "clickhouse":
        from app.services.analytics_sink_clickhouse import ClickHouseAnalyticsSink

        return ClickHouseAnalyticsSink()
    return NullAnalyticsSink()


def get_analytics_sink() -> AnalyticsSink:
    global _SINK
    if _SINK is None:
        _SINK = _build_sink()
    return _SINK


def reset_analytics_sink() -> None:
    global _SINK
    _SINK = None


__all__ = [
    "AnalyticsSink",
    "NdjsonAnalyticsSink",
    "NullAnalyticsSink",
    "get_analytics_sink",
    "reset_analytics_sink",
]
