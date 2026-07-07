"""Hot-store retention: roll aged raw audit events into daily aggregates and
prune them, keeping the primary event table bounded under high volume.

Raw events older than the retention window are aggregated into
`AuditDailyRollup` (per org/day/agent/decision counts) and then deleted from
`audit_events`. Long-term trends and compliance decision-rate history survive
in the rollups (and, if configured, at full fidelity in the cold archive);
the hot table stays small and fast.

Retention is opt-in (`EPHORATE_AUDIT_RETENTION_DAYS`); unset = keep raw forever.
Each pass is bounded by `retention_batch_size` and is safe to re-run — it only
deletes rows it has already rolled up, so the scheduled task simply repeats
until caught up.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, and_, delete, func, or_, select
from sqlalchemy.orm import Session

from app.models import AuditDailyRollup, AuditEvent, MetricEvent

_DELETE_CHUNK = 500


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _chunks(seq: list[str], size: int) -> list[list[str]]:
    return [seq[i : i + size] for i in range(0, len(seq), size)]


def _aged_out_predicate(
    now: datetime,
    retention_days: int | None,
    retention_by_class: dict[str, int],
) -> ColumnElement[bool] | None:
    """Build a WHERE predicate selecting events past their applicable window.

    A classification named in ``retention_by_class`` ages out on its own
    window; everything else uses the default ``retention_days``. Returns None
    when nothing can be pruned (no windows configured)."""

    def cutoff(days: int) -> datetime:
        return _naive_utc(now - timedelta(days=days))

    conds: list[ColumnElement[bool]] = [
        and_(AuditEvent.classification == cls, AuditEvent.timestamp < cutoff(days))
        for cls, days in retention_by_class.items()
    ]
    if retention_days is not None:
        if retention_by_class:
            # Default window applies to any classification without an override.
            conds.append(
                and_(
                    AuditEvent.classification.notin_(list(retention_by_class)),
                    AuditEvent.timestamp < cutoff(retention_days),
                )
            )
        else:
            conds.append(AuditEvent.timestamp < cutoff(retention_days))
    if not conds:
        return None
    return or_(*conds)


def apply_retention(
    session: Session,
    *,
    org_id: str,
    retention_days: int | None,
    now: datetime | None = None,
    batch_size: int = 50_000,
    retention_by_class: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Roll up + prune raw audit events older than their retention window.

    A per-classification override map (``retention_by_class``) ages sensitive
    ("restricted") events out on a tighter window than the default
    ``retention_days`` — classification-aware retention for data minimization.

    Returns {rolled, pruned, buckets, caught_up}. A no-op (all zeros,
    caught_up=True) when no retention window is configured.
    """
    retention_by_class = retention_by_class or {}
    now = now or datetime.now(UTC)
    predicate = _aged_out_predicate(now, retention_days, retention_by_class)
    if predicate is None:
        return {"rolled": 0, "pruned": 0, "buckets": 0, "caught_up": True}

    rows = session.execute(
        select(
            AuditEvent.id,
            AuditEvent.timestamp,
            AuditEvent.agent_id,
            AuditEvent.decision,
        )
        .where(
            AuditEvent.organization_id == org_id,
            predicate,
        )
        .order_by(AuditEvent.timestamp.asc())
        .limit(batch_size)
    ).all()
    if not rows:
        return {"rolled": 0, "pruned": 0, "buckets": 0, "caught_up": True}

    # Aggregate (day, agent, decision) -> count.
    agg: dict[tuple[date, str, str], int] = defaultdict(int)
    ids: list[str] = []
    for r in rows:
        ids.append(r.id)
        day = r.timestamp.date()
        agg[(day, r.agent_id, r.decision)] += 1

    for (day, agent_id, decision), count in agg.items():
        existing = session.execute(
            select(AuditDailyRollup).where(
                AuditDailyRollup.organization_id == org_id,
                AuditDailyRollup.day == day,
                AuditDailyRollup.agent_id == agent_id,
                AuditDailyRollup.decision == decision,
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.count += count
        else:
            session.add(
                AuditDailyRollup(
                    organization_id=org_id,
                    day=day,
                    agent_id=agent_id,
                    decision=decision,
                    count=count,
                )
            )
    session.flush()

    for chunk in _chunks(ids, _DELETE_CHUNK):
        session.execute(delete(AuditEvent).where(AuditEvent.id.in_(chunk)))

    return {
        "rolled": len(ids),
        "pruned": len(ids),
        "buckets": len(agg),
        # If we filled the batch there may be more to do next pass.
        "caught_up": len(rows) < batch_size,
    }


def telemetry_stats(session: Session, org_id: str) -> dict[str, Any]:
    """Ops snapshot of the event store for one org."""
    hot_audit = int(
        session.execute(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.organization_id == org_id)
        ).scalar_one()
    )
    hot_metric = int(
        session.execute(
            select(func.count())
            .select_from(MetricEvent)
            .where(MetricEvent.organization_id == org_id)
        ).scalar_one()
    )
    oldest, newest = session.execute(
        select(func.min(AuditEvent.timestamp), func.max(AuditEvent.timestamp)).where(
            AuditEvent.organization_id == org_id
        )
    ).one()
    by_class = {
        str(cls): int(count)
        for cls, count in session.execute(
            select(AuditEvent.classification, func.count())
            .where(AuditEvent.organization_id == org_id)
            .group_by(AuditEvent.classification)
        ).all()
    }
    rollup_total, rollup_days, rollup_oldest = session.execute(
        select(
            func.coalesce(func.sum(AuditDailyRollup.count), 0),
            func.count(func.distinct(AuditDailyRollup.day)),
            func.min(AuditDailyRollup.day),
        ).where(AuditDailyRollup.organization_id == org_id)
    ).one()

    def _iso(v: Any) -> str | None:
        return v.isoformat() if v is not None else None

    return {
        "hot_audit_events": hot_audit,
        "hot_metric_events": hot_metric,
        "hot_audit_by_classification": by_class,
        "oldest_hot_event": _iso(oldest),
        "newest_hot_event": _iso(newest),
        "rollup_events_total": int(rollup_total or 0),
        "rollup_days": int(rollup_days or 0),
        "rollup_oldest_day": _iso(rollup_oldest),
    }


__all__ = ["apply_retention", "telemetry_stats"]
