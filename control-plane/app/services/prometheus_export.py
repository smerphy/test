"""Prometheus exposition endpoint.

Renders a snapshot of current-org metrics in the Prometheus text
format. We deliberately compute on-demand rather than maintaining
in-process counters: the source of truth is the SQL table; Prometheus
scrapes get the consistent number that the dashboard shows.

Series exposed:
  - praetor_requests_total{model, status, agent_id}
  - praetor_tokens_total{model, kind} (input/output/cache_read/cache_write)
  - praetor_cost_usd_total{model}
  - praetor_request_duration_ms_summary{model, quantile="0.5|0.95|0.99"}
  - praetor_alert_rules{state="firing|ok"}
  - praetor_alert_events_total{severity}

Scrape window is the last 24h to avoid full-table scans; configurable
via `PRAETOR_PROM_WINDOW_HOURS`.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from io import StringIO

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AlertEvent, AlertRule, AlertState, MetricEvent


def _strip_tz(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(d: dict[str, str]) -> str:
    if not d:
        return ""
    body = ",".join(f'{k}="{_escape(v)}"' for k, v in d.items())
    return "{" + body + "}"


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    vs = sorted(values)
    n = len(vs)
    return vs[min(n - 1, int(q * n))]


def render_prometheus(session: Session, *, org_id: str) -> str:
    hours = int(os.environ.get("PRAETOR_PROM_WINDOW_HOURS", "24"))
    since = _strip_tz(datetime.now(UTC) - timedelta(hours=hours))

    out = StringIO()

    # praetor_requests_total
    stmt = (
        select(
            MetricEvent.model,
            MetricEvent.status,
            MetricEvent.agent_id,
            func.count().label("n"),
        )
        .where(
            MetricEvent.organization_id == org_id,
            MetricEvent.timestamp >= since,
        )
        .group_by(MetricEvent.model, MetricEvent.status, MetricEvent.agent_id)
    )
    rows = list(session.execute(stmt).all())
    out.write("# HELP praetor_requests_total Claude API calls observed.\n")
    out.write("# TYPE praetor_requests_total counter\n")
    for model, status, agent_id, n in rows:
        labels = _labels({"model": model, "status": status, "agent_id": agent_id})
        out.write(f"praetor_requests_total{labels} {n}\n")

    # praetor_tokens_total + praetor_cost_usd_total
    tokens_stmt = (
        select(
            MetricEvent.model,
            func.coalesce(func.sum(MetricEvent.input_tokens), 0),
            func.coalesce(func.sum(MetricEvent.output_tokens), 0),
            func.coalesce(func.sum(MetricEvent.cache_read_tokens), 0),
            func.coalesce(func.sum(MetricEvent.cache_write_tokens), 0),
            func.coalesce(func.sum(MetricEvent.cost_usd), 0.0),
        )
        .where(
            MetricEvent.organization_id == org_id,
            MetricEvent.timestamp >= since,
        )
        .group_by(MetricEvent.model)
    )
    out.write("# HELP praetor_tokens_total Tokens consumed, summed by model + kind.\n")
    out.write("# TYPE praetor_tokens_total counter\n")
    out.write("# HELP praetor_cost_usd_total Dollar spend, summed by model.\n")
    out.write("# TYPE praetor_cost_usd_total counter\n")
    for model, in_t, out_t, cr_t, cw_t, cost in session.execute(tokens_stmt).all():
        for kind, value in (
            ("input", in_t),
            ("output", out_t),
            ("cache_read", cr_t),
            ("cache_write", cw_t),
        ):
            out.write(
                f"praetor_tokens_total{_labels({'model': model, 'kind': kind})} {int(value)}\n"
            )
        out.write(
            f"praetor_cost_usd_total{_labels({'model': model})} {float(cost):.6f}\n"
        )

    # Duration summary (p50/p95/p99) per model. Sampled from the in-window
    # rows to bound the cost; a real scrape every 30s sees fresh data.
    dur_stmt = select(MetricEvent.model, MetricEvent.duration_ms).where(
        MetricEvent.organization_id == org_id,
        MetricEvent.timestamp >= since,
    )
    per_model: dict[str, list[float]] = {}
    for model, dur in session.execute(dur_stmt).all():
        per_model.setdefault(model, []).append(float(dur))
    out.write("# HELP praetor_request_duration_ms_summary Claude call latency (last window).\n")
    out.write("# TYPE praetor_request_duration_ms_summary summary\n")
    for model, vs in per_model.items():
        for q in (0.5, 0.95, 0.99):
            qlabels = _labels({"model": model, "quantile": str(q)})
            out.write(
                f"praetor_request_duration_ms_summary{qlabels} "
                f"{_quantile(vs, q):.3f}\n"
            )
        out.write(
            f"praetor_request_duration_ms_summary_count{_labels({'model': model})} {len(vs)}\n"
        )
        out.write(
            f"praetor_request_duration_ms_summary_sum{_labels({'model': model})} {sum(vs):.3f}\n"
        )

    # Alert state.
    rule_states = list(
        session.execute(
            select(AlertRule.enabled, func.count())
            .where(AlertRule.organization_id == org_id)
            .group_by(AlertRule.enabled)
        ).all()
    )
    out.write("# HELP praetor_alert_rules Alert rule count by enabled state.\n")
    out.write("# TYPE praetor_alert_rules gauge\n")
    for enabled, n in rule_states:
        out.write(
            f"praetor_alert_rules{_labels({'enabled': str(bool(enabled)).lower()})} {n}\n"
        )

    firings = list(
        session.execute(
            select(AlertEvent.state, func.count())
            .where(
                AlertEvent.organization_id == org_id,
                AlertEvent.fired_at >= since,
            )
            .group_by(AlertEvent.state)
        ).all()
    )
    out.write("# HELP praetor_alert_events_total Alert firings in the window, by state.\n")
    out.write("# TYPE praetor_alert_events_total counter\n")
    for state, n in firings:
        state_value = state.value if hasattr(state, "value") else str(state)
        out.write(
            f"praetor_alert_events_total{_labels({'state': state_value})} {n}\n"
        )

    return out.getvalue()


def open_alert_count(session: Session, *, org_id: str) -> int:
    """Number of currently-firing (un-resolved) alerts for the org."""
    return int(
        session.execute(
            select(func.count())
            .select_from(AlertEvent)
            .where(
                AlertEvent.organization_id == org_id,
                AlertEvent.state == AlertState.FIRING,
            )
        ).scalar_one()
        or 0
    )


__all__ = ["open_alert_count", "render_prometheus"]
