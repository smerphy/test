"""Metrics ingestion + time-bucketed aggregation.

Aggregation is computed in Python over a single indexed scan rather
than pushed to the database. Postgres `date_bin` would be more
efficient at scale; we'll switch to it once we have a real workload.
For SQLite (tests) we have no choice.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import MetricEvent
from app.schemas import MetricBucket, MetricEventIn
from app.services.cost import compute_cost_usd


def _to_utc(ts: datetime) -> datetime:
    """Normalize a timestamp to UTC before storage.

    The `MetricEvent.timestamp` column is `DateTime(timezone=True)`, but
    SQLite drops the offset on write *without* converting to UTC, so a
    non-UTC aware timestamp would be persisted at the wrong instant and
    skew every window query, bucket, and alert. Convert here so the stored
    wall-clock value is always UTC. Naive input is assumed to already be UTC.
    """
    if ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC)


def ingest_metric(
    session: Session, *, org_id: str, event: MetricEventIn
) -> MetricEvent:
    cost = event.cost_usd
    if cost is None:
        cost = compute_cost_usd(
            model=event.model,
            input_tokens=event.input_tokens,
            output_tokens=event.output_tokens,
            cache_read_tokens=event.cache_read_tokens,
            cache_write_tokens=event.cache_write_tokens,
        )
    row = MetricEvent(
        organization_id=org_id,
        timestamp=_to_utc(event.timestamp),
        agent_id=event.agent_id,
        session_id=event.session_id,
        model=event.model,
        operation=event.operation,
        request_id=event.request_id,
        duration_ms=event.duration_ms,
        input_tokens=event.input_tokens,
        output_tokens=event.output_tokens,
        cache_read_tokens=event.cache_read_tokens,
        cache_write_tokens=event.cache_write_tokens,
        cost_usd=cost,
        status=event.status,
        stop_reason=event.stop_reason,
        error_type=event.error_type,
        tools_used=list(event.tools_used),
        metadata_=dict(event.metadata),
    )
    session.add(row)
    session.flush()
    return row


def _bucket_floor(ts: datetime, bucket_size: timedelta) -> datetime:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    seconds = int(bucket_size.total_seconds())
    epoch = int(ts.timestamp())
    floored = epoch - (epoch % seconds)
    return datetime.fromtimestamp(floored, tz=UTC)


def aggregate_metrics(
    session: Session,
    *,
    org_id: str,
    since: datetime,
    until: datetime,
    bucket_minutes: int,
    group_by: str | None = None,
    filter_model: str | None = None,
    filter_agent_id: str | None = None,
) -> tuple[list[MetricBucket], dict[str, list[MetricBucket]]]:
    """Return (overall_buckets, per_group_buckets).

    `group_by` ∈ {"model", "agent_id", "project_id"}. When None,
    `per_group_buckets` is empty.
    """
    bucket_size = timedelta(minutes=bucket_minutes)
    stmt = (
        select(MetricEvent)
        .where(
            MetricEvent.organization_id == org_id,
            MetricEvent.timestamp >= since,
            MetricEvent.timestamp < until,
        )
        .order_by(MetricEvent.timestamp.asc())
    )
    if filter_model:
        stmt = stmt.where(MetricEvent.model == filter_model)
    if filter_agent_id:
        stmt = stmt.where(MetricEvent.agent_id == filter_agent_id)

    overall: dict[datetime, dict[str, float]] = defaultdict(
        lambda: dict(req=0.0, in_=0.0, out=0.0, cost=0.0, errs=0.0, dur=0.0)
    )
    by_group: dict[str, dict[datetime, dict[str, float]]] = defaultdict(
        lambda: defaultdict(
            lambda: dict(req=0.0, in_=0.0, out=0.0, cost=0.0, errs=0.0, dur=0.0)
        )
    )

    for ev in session.execute(stmt).scalars():
        bucket = _bucket_floor(ev.timestamp, bucket_size)
        agg = overall[bucket]
        agg["req"] += 1
        agg["in_"] += ev.input_tokens
        agg["out"] += ev.output_tokens
        agg["cost"] += ev.cost_usd
        agg["dur"] += ev.duration_ms
        if ev.status != "success":
            agg["errs"] += 1

        if group_by:
            key = _group_key(ev, group_by)
            g = by_group[key][bucket]
            g["req"] += 1
            g["in_"] += ev.input_tokens
            g["out"] += ev.output_tokens
            g["cost"] += ev.cost_usd
            g["dur"] += ev.duration_ms
            if ev.status != "success":
                g["errs"] += 1

    def _materialize(buckets: dict[datetime, dict[str, float]]) -> list[MetricBucket]:
        out = []
        for ts in sorted(buckets):
            agg = buckets[ts]
            req = max(int(agg["req"]), 1)
            in_t = int(agg["in_"])
            out_t = int(agg["out"])
            out.append(
                MetricBucket(
                    bucket_start=ts,
                    request_count=int(agg["req"]),
                    input_tokens=in_t,
                    output_tokens=out_t,
                    total_tokens=in_t + out_t,
                    cost_usd=round(agg["cost"], 6),
                    error_count=int(agg["errs"]),
                    avg_duration_ms=agg["dur"] / req,
                )
            )
        return out

    overall_list = _materialize(overall)
    grouped = {k: _materialize(v) for k, v in by_group.items()} if group_by else {}
    return overall_list, grouped


def _group_key(ev: MetricEvent, group_by: str) -> str:
    if group_by == "model":
        return ev.model
    if group_by == "agent_id":
        return ev.agent_id
    if group_by == "project_id":
        return ev.project_id or "<none>"
    return "<unknown>"


__all__ = ["aggregate_metrics", "ingest_metric"]
