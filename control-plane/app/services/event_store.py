"""Pluggable telemetry event sinks (the cold tier of the event store).

Raw audit/metric events land in the hot SQL store (queryable, but bounded by
retention). To scale out under high volume they are *also* streamed, best
effort, to a cheap append-only cold tier as partitioned NDJSON:

    {root}/{kind}/org={org_id}/date=YYYY-MM-DD/{kind}-YYYY-MM-DD.ndjson[.gz]

The layout is Hive-style partitioning, so the archive root can be an
object-store mount (s3fs/gcsfuse) queried directly by Athena / BigQuery /
DuckDB, or shipped to a lakehouse. Archival never blocks or fails ingestion:
a broken sink degrades to "hot store only".

`get_event_sink()` selects the sink from settings — a `NullSink` when no
archive is configured (the default), so existing deployments are unaffected.
"""

from __future__ import annotations

import glob
import gzip
import json
import os
from collections.abc import Iterator
from datetime import datetime
from typing import Any, Protocol

from app.settings import Settings, get_settings

Record = dict[str, Any]


class EventSink(Protocol):
    def archive(
        self, kind: str, org_id: str, records: list[Record], now: datetime
    ) -> int:
        """Persist `records` to the cold tier. Returns the number written."""
        ...

    @property
    def enabled(self) -> bool:
        ...


class NullSink:
    """No-op sink used when archival is disabled."""

    enabled = False

    def archive(
        self, kind: str, org_id: str, records: list[Record], now: datetime
    ) -> int:
        return 0


class ArchiveSink:
    """Append-only NDJSON archive, Hive-partitioned by kind/org/date."""

    enabled = True

    def __init__(self, root: str, *, gzip_enabled: bool = True) -> None:
        self.root = root
        self.gzip_enabled = gzip_enabled

    def _safe_org(self, org_id: str) -> str:
        # org_id comes from our own DB (uuid); still guard against traversal.
        return org_id.replace("/", "_").replace("..", "_")

    def _partition_path(self, kind: str, org_id: str, day: str) -> str:
        return os.path.join(
            self.root,
            kind,
            f"org={self._safe_org(org_id)}",
            f"date={day}",
        )

    def iter_records(self, kind: str, org_id: str) -> Iterator[Record]:
        """Read every archived record for (kind, org) back out of the cold tier,
        across all date partitions. gzip members decode transparently."""
        base = os.path.join(self.root, kind, f"org={self._safe_org(org_id)}")
        # Deterministic order: by date partition, then by file name.
        for path in sorted(glob.glob(os.path.join(base, "date=*", f"{kind}-*"))):
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        yield json.loads(line)

    def archive(
        self, kind: str, org_id: str, records: list[Record], now: datetime
    ) -> int:
        if not records:
            return 0
        day = now.strftime("%Y-%m-%d")
        directory = self._partition_path(kind, org_id, day)
        os.makedirs(directory, exist_ok=True)
        suffix = ".ndjson.gz" if self.gzip_enabled else ".ndjson"
        path = os.path.join(directory, f"{kind}-{day}{suffix}")
        payload = "".join(
            json.dumps(r, ensure_ascii=False, default=str) + "\n" for r in records
        ).encode("utf-8")
        if self.gzip_enabled:
            # Append a gzip member; concatenated members decode as one stream.
            with open(path, "ab") as fh:
                fh.write(gzip.compress(payload))
        else:
            with open(path, "ab") as fh:
                fh.write(payload)
        return len(records)


def _build_sink(settings: Settings) -> EventSink:
    if settings.event_archive_dir:
        return ArchiveSink(
            settings.event_archive_dir,
            gzip_enabled=settings.event_archive_gzip,
        )
    return NullSink()


# Cache the sink per-process; tests reconfigure via get_event_sink.cache_clear().
_SINK: EventSink | None = None


def get_event_sink() -> EventSink:
    global _SINK
    if _SINK is None:
        _SINK = _build_sink(get_settings())
    return _SINK


def reset_event_sink() -> None:
    """Drop the cached sink (used by tests after changing settings)."""
    global _SINK
    _SINK = None


def archive_events(kind: str, org_id: str, records: list[Record]) -> int:
    """Best-effort archival of already-accepted events. Never raises."""
    sink = get_event_sink()
    if not sink.enabled or not records:
        return 0
    try:
        return sink.archive(kind, org_id, records, datetime.now())
    except OSError:
        # Cold-tier failure must never break hot ingestion.
        return 0


def read_archive(kind: str, org_id: str) -> Iterator[Record]:
    """Iterate archived records for (kind, org). Empty when archival is off."""
    sink = get_event_sink()
    if isinstance(sink, ArchiveSink):
        yield from sink.iter_records(kind, org_id)


__all__ = [
    "ArchiveSink",
    "EventSink",
    "NullSink",
    "archive_events",
    "get_event_sink",
    "read_archive",
    "reset_event_sink",
]
