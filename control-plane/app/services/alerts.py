"""Alert rule evaluator + delivery.

Each `AlertRule` is evaluated against a rolling window of `MetricEvent`
rows. When the aggregate crosses the threshold (respecting cooldown),
an `AlertEvent` row is created and routed to the configured channel.

Delivery is best-effort with structured error capture: a routing
failure marks `delivered=False` and stores the error on the row so
the inbox UI can show it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models import (
    AlertAggregation,
    AlertChannel,
    AlertComparison,
    AlertEvent,
    AlertMetric,
    AlertRule,
    AlertState,
    MetricEvent,
)


def _strip_tz(value: datetime) -> datetime:
    """Strip tz from a datetime for comparison against `DateTime(timezone=True)`
    columns on SQLite (which silently drops the offset on storage).
    Postgres preserves it end-to-end; this is a no-op there in practice
    because the parameter binding handles the conversion.
    """
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _window_bounds(rule: AlertRule, now: datetime) -> tuple[datetime, datetime]:
    return _strip_tz(now - timedelta(minutes=rule.window_minutes)), _strip_tz(now)


def _filter_stmt(
    rule: AlertRule, since: datetime, until: datetime
) -> Select[tuple[MetricEvent]]:
    stmt = select(MetricEvent).where(
        MetricEvent.organization_id == rule.organization_id,
        MetricEvent.timestamp >= since,
        MetricEvent.timestamp < until,
    )
    if rule.filter_model:
        stmt = stmt.where(MetricEvent.model == rule.filter_model)
    if rule.filter_agent_id:
        stmt = stmt.where(MetricEvent.agent_id == rule.filter_agent_id)
    return stmt


def _select_metric_value(ev: MetricEvent, metric: AlertMetric) -> float:
    match metric:
        case AlertMetric.COST_USD:
            return ev.cost_usd
        case AlertMetric.INPUT_TOKENS:
            return float(ev.input_tokens)
        case AlertMetric.OUTPUT_TOKENS:
            return float(ev.output_tokens)
        case AlertMetric.TOTAL_TOKENS:
            return float(ev.input_tokens + ev.output_tokens)
        case AlertMetric.DURATION_MS:
            return float(ev.duration_ms)
        case AlertMetric.REQUEST_COUNT:
            return 1.0
        case AlertMetric.ERROR_COUNT:
            return 1.0 if ev.status != "success" else 0.0
        case AlertMetric.ERROR_RATE:
            return 1.0 if ev.status != "success" else 0.0
        case AlertMetric.DENY_COUNT:
            return 1.0 if ev.status == "denied" else 0.0


def _aggregate(values: list[float], agg: AlertAggregation) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    match agg:
        case AlertAggregation.SUM:
            return sum(values)
        case AlertAggregation.AVG:
            return sum(values) / n
        case AlertAggregation.COUNT | AlertAggregation.RATE:
            return float(n)
        case AlertAggregation.MAX:
            return max(values)
        case AlertAggregation.P50:
            return sorted_vals[min(n - 1, int(0.5 * n))]
        case AlertAggregation.P95:
            return sorted_vals[min(n - 1, int(0.95 * n))]
        case AlertAggregation.P99:
            return sorted_vals[min(n - 1, int(0.99 * n))]


def _compare(value: float, threshold: float, op: AlertComparison) -> bool:
    match op:
        case AlertComparison.GT:
            return value > threshold
        case AlertComparison.GTE:
            return value >= threshold
        case AlertComparison.LT:
            return value < threshold
        case AlertComparison.LTE:
            return value <= threshold


def _group_key(ev: MetricEvent, group_by: str | None) -> str | None:
    if group_by is None:
        return None
    if group_by == "model":
        return ev.model
    if group_by == "agent_id":
        return ev.agent_id
    if group_by == "project_id":
        return ev.project_id or "<none>"
    return None


def evaluate_rule(
    session: Session,
    rule: AlertRule,
    *,
    now: datetime | None = None,
    http_client: httpx.Client | None = None,
) -> list[AlertEvent]:
    """Evaluate one rule. Creates + routes AlertEvent rows for each
    group whose aggregate crosses the threshold. Returns the created
    events (may be empty).
    """
    if not rule.enabled:
        return []
    now = now or datetime.now(UTC)
    since, until = _window_bounds(rule, now)

    # Cooldown: skip if any AlertEvent fired in the last `cooldown_minutes`.
    if rule.cooldown_minutes > 0:
        recent = session.execute(
            select(func.max(AlertEvent.fired_at)).where(
                AlertEvent.rule_id == rule.id
            )
        ).scalar_one_or_none()
        if recent is not None:
            if recent.tzinfo is None:
                recent = recent.replace(tzinfo=UTC)
            if now - recent < timedelta(minutes=rule.cooldown_minutes):
                rule.last_evaluated_at = now
                return []

    rows = list(session.execute(_filter_stmt(rule, since, until)).scalars())

    # Auto-resolve: any firing AlertEvent whose group is no longer above
    # threshold gets marked resolved. Must run before we re-fire so the
    # cooldown window of the new firing isn't fooled by a stale one.
    _auto_resolve_firings(session, rule, rows, now)

    if rule.metric is AlertMetric.ERROR_RATE:
        # Special handling: ratio of (error count) / (total count).
        return _eval_error_rate(session, rule, rows, now, http_client)

    # Group + aggregate.
    grouped: dict[str | None, list[float]] = {}
    for ev in rows:
        key = _group_key(ev, rule.group_by)
        grouped.setdefault(key, []).append(_select_metric_value(ev, rule.metric))

    fired: list[AlertEvent] = []
    for key, values in grouped.items():
        agg = _aggregate(values, rule.aggregation)
        if not _compare(agg, rule.threshold, rule.comparison):
            continue
        event = AlertEvent(
            organization_id=rule.organization_id,
            rule_id=rule.id,
            fired_at=now,
            state=AlertState.FIRING,
            metric_value=agg,
            threshold=rule.threshold,
            group_key=key,
        )
        session.add(event)
        session.flush()
        _route(event, rule, http_client)
        fired.append(event)

    rule.last_evaluated_at = now
    session.flush()
    return fired


def _auto_resolve_firings(
    session: Session,
    rule: AlertRule,
    rows: list[MetricEvent],
    now: datetime,
) -> None:
    """For each currently-firing AlertEvent on this rule, check if the
    same group is back below threshold; if so, mark resolved.

    Acknowledged firings stay acknowledged — but if they recover, they
    move from ACKNOWLEDGED to RESOLVED too.
    """
    # Build per-group aggregate from the current window.
    grouped: dict[str | None, list[float]] = {}
    for ev in rows:
        key = _group_key(ev, rule.group_by)
        grouped.setdefault(key, []).append(_select_metric_value(ev, rule.metric))

    open_firings = list(
        session.execute(
            select(AlertEvent).where(
                AlertEvent.rule_id == rule.id,
                AlertEvent.state.in_([AlertState.FIRING, AlertState.ACKNOWLEDGED]),
            )
        ).scalars()
    )
    for fire in open_firings:
        vs = grouped.get(fire.group_key, [])
        agg = _aggregate(vs, rule.aggregation)
        if not _compare(agg, rule.threshold, rule.comparison):
            fire.state = AlertState.RESOLVED
            fire.resolved_at = now
    session.flush()


def _eval_error_rate(
    session: Session,
    rule: AlertRule,
    rows: list[MetricEvent],
    now: datetime,
    http_client: httpx.Client | None,
) -> list[AlertEvent]:
    grouped: dict[str | None, tuple[int, int]] = {}  # key -> (errors, total)
    for ev in rows:
        key = _group_key(ev, rule.group_by)
        errs, total = grouped.get(key, (0, 0))
        grouped[key] = (
            errs + (1 if ev.status != "success" else 0),
            total + 1,
        )

    fired: list[AlertEvent] = []
    for key, (errs, total) in grouped.items():
        if total == 0:
            continue
        rate = errs / total
        if not _compare(rate, rule.threshold, rule.comparison):
            continue
        event = AlertEvent(
            organization_id=rule.organization_id,
            rule_id=rule.id,
            fired_at=now,
            state=AlertState.FIRING,
            metric_value=rate,
            threshold=rule.threshold,
            group_key=key,
        )
        session.add(event)
        session.flush()
        _route(event, rule, http_client)
        fired.append(event)
    rule.last_evaluated_at = now
    session.flush()
    return fired


def _route(
    event: AlertEvent,
    rule: AlertRule,
    http_client: httpx.Client | None,
) -> None:
    """Deliver an alert. Failures are captured on the event row, not raised."""
    payload = _build_payload(event, rule)
    event.payload = payload
    client = http_client or httpx.Client(timeout=10.0)
    try:
        if rule.channel is AlertChannel.SLACK:
            r = client.post(rule.target, json=payload["slack"])
            r.raise_for_status()
        elif rule.channel is AlertChannel.PAGERDUTY:
            r = client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json={
                    "routing_key": rule.target,
                    "event_action": "trigger",
                    "payload": payload["pagerduty"],
                    "dedup_key": f"praetor:{rule.id}:{event.group_key or 'all'}",
                },
            )
            r.raise_for_status()
        elif rule.channel is AlertChannel.WEBHOOK:
            r = client.post(rule.target, json=payload["raw"])
            r.raise_for_status()
        elif rule.channel is AlertChannel.EMAIL:
            # Email transport not bundled — leave undelivered with a
            # clear error so SREs know to wire SES/SMTP themselves.
            raise NotImplementedError(
                "email channel requires an SMTP/SES transport; not bundled in MVP"
            )
        event.delivered = True
    except Exception as exc:
        event.delivered = False
        event.delivery_error = f"{type(exc).__name__}: {exc}"


def _enum_value(v: Any) -> str:
    """Tolerant accessor: handles both raw strings (from SQLAlchemy's
    `Enum(native_enum=False)` round-trip on some drivers) and StrEnum
    instances."""
    return v.value if hasattr(v, "value") else str(v)


def _build_payload(event: AlertEvent, rule: AlertRule) -> dict[str, Any]:
    severity = _enum_value(rule.severity)
    title = f"[{severity.upper()}] {rule.name}"
    detail_lines = [
        f"Metric: {_enum_value(rule.metric)} ({_enum_value(rule.aggregation)})",
        f"Window: last {rule.window_minutes} min",
        (
            f"Value: {event.metric_value:.4g}  vs  threshold "
            f"{rule.threshold:.4g} ({_enum_value(rule.comparison)})"
        ),
    ]
    if event.group_key:
        detail_lines.append(f"Group: {rule.group_by}={event.group_key}")
    detail = "\n".join(detail_lines)
    raw = {
        "id": event.id,
        "rule_id": rule.id,
        "rule_name": rule.name,
        "severity": severity,
        "metric": _enum_value(rule.metric),
        "aggregation": _enum_value(rule.aggregation),
        "window_minutes": rule.window_minutes,
        "comparison": _enum_value(rule.comparison),
        "threshold": rule.threshold,
        "value": event.metric_value,
        "group_by": rule.group_by,
        "group_key": event.group_key,
        "fired_at": event.fired_at.isoformat(),
    }
    return {
        "raw": raw,
        "slack": {
            "text": title,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": title}},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"```\n{detail}\n```"},
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"praetor alert · `{rule.id}`"}
                    ],
                },
            ],
        },
        "pagerduty": {
            "summary": f"{title} — {detail_lines[2]}",
            "severity": severity if severity in ("warning", "critical") else "info",
            "source": "praetor",
            "custom_details": raw,
        },
    }


__all__ = ["evaluate_rule"]
