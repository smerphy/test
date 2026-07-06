"""The event-log abstraction and its durable SQL-backed default.

``EventLog`` is the ingest front: producers ``append`` records to a topic under
a ``partition_key``; consumer groups ``poll`` for the next ordered batch and
``commit`` their offset. It is deliberately backend-agnostic — the default
``SqlEventLog`` stores the log in Postgres/SQLite (no extra infrastructure),
and a Kafka/Redpanda adapter (see ``app.services.eventlog_kafka``) implements
the same three methods for high-volume production.

Delivery is at-least-once: a consumer that crashes after processing but before
committing simply reprocesses, so every downstream materializer must be
idempotent (the hot store dedups audit events on ``(org, hash)``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import LogOffset, LogRecord

Record = dict[str, Any]

# Topic names.
TOPIC_AUDIT = "audit"
TOPIC_METRIC = "metric"


@dataclass(frozen=True)
class LoggedRecord:
    """A record read back from the log, with its offset."""

    offset: int
    organization_id: str
    partition_key: str
    payload: Record


class EventLog(Protocol):
    def append(
        self, topic: str, org_id: str, partition_key: str, records: list[Record]
    ) -> int:
        """Append records to a topic/partition. Returns the number appended."""
        ...

    def poll(
        self, topic: str, consumer_group: str, max_records: int = 500
    ) -> list[LoggedRecord]:
        """Read the next ordered batch past the group's committed offset."""
        ...

    def commit(self, topic: str, consumer_group: str, offset: int) -> None:
        """Advance the group's committed offset."""
        ...

    def lag(self, topic: str, consumer_group: str) -> int:
        """Records past the group's committed offset (consumer backlog)."""
        ...


class SqlEventLog:
    """Durable partitioned log on the primary database.

    Each method manages its own transaction so the log is the system of record
    independent of any request-scoped session.
    """

    def append(
        self, topic: str, org_id: str, partition_key: str, records: list[Record]
    ) -> int:
        if not records:
            return 0
        with SessionLocal() as session:
            session.add_all(
                LogRecord(
                    topic=topic,
                    organization_id=org_id,
                    partition_key=partition_key,
                    payload=rec,
                )
                for rec in records
            )
            session.commit()
        return len(records)

    def _committed_offset(
        self, session: Session, topic: str, consumer_group: str
    ) -> int:
        row = session.get(LogOffset, (topic, consumer_group))
        return row.last_offset if row is not None else 0

    def poll(
        self, topic: str, consumer_group: str, max_records: int = 500
    ) -> list[LoggedRecord]:
        with SessionLocal() as session:
            last = self._committed_offset(session, topic, consumer_group)
            rows = session.execute(
                select(LogRecord)
                .where(LogRecord.topic == topic, LogRecord.id > last)
                .order_by(LogRecord.id.asc())
                .limit(max_records)
            ).scalars()
            return [
                LoggedRecord(
                    offset=r.id,
                    organization_id=r.organization_id,
                    partition_key=r.partition_key,
                    payload=r.payload,
                )
                for r in rows
            ]

    def commit(self, topic: str, consumer_group: str, offset: int) -> None:
        with SessionLocal() as session:
            # Portable upsert (get-or-create); never move the offset backwards.
            row = session.get(LogOffset, (topic, consumer_group))
            if row is None:
                session.add(
                    LogOffset(
                        topic=topic,
                        consumer_group=consumer_group,
                        last_offset=offset,
                    )
                )
            elif offset > row.last_offset:
                row.last_offset = offset
            session.commit()

    def lag(self, topic: str, consumer_group: str) -> int:
        with SessionLocal() as session:
            last = self._committed_offset(session, topic, consumer_group)
            return int(
                session.execute(
                    select(func.count())
                    .select_from(LogRecord)
                    .where(LogRecord.topic == topic, LogRecord.id > last)
                ).scalar_one()
            )


_LOG: EventLog | None = None


def get_event_log() -> EventLog:
    """Return the configured log backend (cached per process)."""
    global _LOG
    if _LOG is None:
        from app.settings import get_settings

        backend = get_settings().log_backend
        if backend == "kafka":
            from app.services.eventlog_kafka import KafkaEventLog

            _LOG = KafkaEventLog()
        else:
            _LOG = SqlEventLog()
    return _LOG


def reset_event_log() -> None:
    """Drop the cached log (tests reconfigure the backend)."""
    global _LOG
    _LOG = None


__all__ = [
    "TOPIC_AUDIT",
    "TOPIC_METRIC",
    "EventLog",
    "LoggedRecord",
    "SqlEventLog",
    "get_event_log",
    "reset_event_log",
]
