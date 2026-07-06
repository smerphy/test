"""Producers + consumers around the event log (the CQRS glue).

Producers publish accepted-but-not-yet-materialized events to the log; consumer
groups drain it into the stores. Two groups read every topic independently:

* ``hot-store``  — materializes the Postgres hot store (analyst/search view)
  by replaying each record through the normal ingest path (hash-chain verify +
  dedup), so it is exactly consistent with direct ingestion.
* ``analytics``  — writes each record to the columnar analytics sink.

Delivery is at-least-once; both materializers are idempotent (audit dedups on
``(org, hash)``; a poison record is skipped rather than blocking the group).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from app.db import SessionLocal
from app.schemas import AuditEventIn, MetricEventIn
from app.services.analytics_sink import get_analytics_sink
from app.services.audit_ingest import ingest_event
from app.services.eventlog import (
    TOPIC_AUDIT,
    TOPIC_METRIC,
    LoggedRecord,
    get_event_log,
)
from app.services.metrics import ingest_metric

GROUP_HOT = "hot-store"
GROUP_ANALYTICS = "analytics"


# --- producers --------------------------------------------------------------
def publish_audit(org_id: str, events: list[AuditEventIn]) -> int:
    """Append audit events to the log, partitioned by (agent, session) so each
    chain keeps arrival order."""
    log = get_event_log()
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        key = f"{org_id}:{ev.agent_id}:{ev.session_id}"
        groups[key].append(ev.model_dump(mode="json"))
    return sum(
        log.append(TOPIC_AUDIT, org_id, key, recs) for key, recs in groups.items()
    )


def publish_metric(org_id: str, events: list[MetricEventIn]) -> int:
    """Append metric events to the log, partitioned by org."""
    records = [ev.model_dump(mode="json") for ev in events]
    return get_event_log().append(TOPIC_METRIC, org_id, org_id, records)


# --- consumers --------------------------------------------------------------
def _materialize_audit_hot(records: list[LoggedRecord]) -> None:
    with SessionLocal() as session:
        for r in records:
            try:
                ingest_event(
                    session,
                    org_id=r.organization_id,
                    event=AuditEventIn.model_validate(r.payload),
                )
            except Exception:
                # Poison/duplicate record: skip. Idempotency + at-least-once
                # mean re-materialization is safe; one bad record must not
                # wedge the whole group.
                continue
        session.commit()


def _materialize_metric_hot(records: list[LoggedRecord]) -> None:
    with SessionLocal() as session:
        for r in records:
            try:
                ingest_metric(
                    session,
                    org_id=r.organization_id,
                    event=MetricEventIn.model_validate(r.payload),
                )
            except Exception:
                continue
        session.commit()


# The analytics materializer needs to know which topic it is draining; bind it
# per-topic via a closure rather than threading it through drain()'s signature.
def _analytics_writer(topic: str) -> Callable[[list[LoggedRecord]], None]:
    def _write(records: list[LoggedRecord]) -> None:
        sink = get_analytics_sink()
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in records:
            grouped[r.organization_id].append(r.payload)
        for org_id, payloads in grouped.items():
            sink.write(topic, org_id, payloads)

    return _write


def drain(
    topic: str,
    group: str,
    process: Callable[[list[LoggedRecord]], None],
    max_records: int = 1000,
) -> int:
    """Poll one ordered batch for (topic, group), process it, then commit the
    offset. At-least-once: commit only after successful processing."""
    log = get_event_log()
    records = log.poll(topic, group, max_records)
    if not records:
        return 0
    process(records)
    log.commit(topic, group, records[-1].offset)
    return len(records)


def run_all_consumers(max_records: int = 1000, max_rounds: int = 100) -> dict[str, int]:
    """Drain every (topic, group) until caught up (or max_rounds). Returns the
    per-pair record counts."""
    pairs: list[tuple[str, str, Callable[[list[LoggedRecord]], None]]] = [
        (TOPIC_AUDIT, GROUP_HOT, _materialize_audit_hot),
        (TOPIC_METRIC, GROUP_HOT, _materialize_metric_hot),
        (TOPIC_AUDIT, GROUP_ANALYTICS, _analytics_writer(TOPIC_AUDIT)),
        (TOPIC_METRIC, GROUP_ANALYTICS, _analytics_writer(TOPIC_METRIC)),
    ]
    counts: dict[str, int] = {}
    for topic, group, process in pairs:
        total = 0
        for _ in range(max_rounds):
            n = drain(topic, group, process, max_records)
            total += n
            if n == 0:
                break
        counts[f"{topic}:{group}"] = total
    return counts


__all__ = [
    "GROUP_ANALYTICS",
    "GROUP_HOT",
    "drain",
    "publish_audit",
    "publish_metric",
    "run_all_consumers",
]
