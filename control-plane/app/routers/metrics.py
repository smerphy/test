"""Claude API metrics: ingestion + search + time-bucketed aggregation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from annotated_types import Len
from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.models import MetricEvent, Organization, Role
from app.schemas import (
    MetricAggregateResponse,
    MetricEventIn,
    MetricEventOut,
    MetricIngestResult,
)
from app.services.metrics import aggregate_metrics, ingest_metric
from app.services.prometheus_export import render_prometheus

router = APIRouter(tags=["metrics"])


@router.post(
    "/metrics/events",
    response_model=MetricIngestResult,
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_events(
    events: Annotated[list[MetricEventIn], Len(max_length=1000)],
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> MetricIngestResult:
    accepted = 0
    errors: list[str] = []
    for raw in events:
        try:
            ingest_metric(session, org_id=org.id, event=raw)
            accepted += 1
        except ValueError as exc:
            errors.append(f"{raw.agent_id}@{raw.timestamp.isoformat()}: {exc}")
    return MetricIngestResult(
        accepted=accepted, rejected=len(events) - accepted, errors=errors
    )


@router.get("/metrics/events", response_model=list[MetricEventOut])
def search_events(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    model: str | None = None,
    agent_id: str | None = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[MetricEvent]:
    stmt = (
        select(MetricEvent)
        .where(MetricEvent.organization_id == org.id)
        .order_by(MetricEvent.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )
    if model:
        stmt = stmt.where(MetricEvent.model == model)
    if agent_id:
        stmt = stmt.where(MetricEvent.agent_id == agent_id)
    if status_filter:
        stmt = stmt.where(MetricEvent.status == status_filter)
    if since:
        stmt = stmt.where(MetricEvent.timestamp >= since)
    if until:
        stmt = stmt.where(MetricEvent.timestamp <= until)
    return list(session.execute(stmt).scalars().all())


@router.get("/metrics/aggregate", response_model=MetricAggregateResponse)
def aggregate(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    since: datetime | None = None,
    until: datetime | None = None,
    bucket_minutes: Annotated[int, Query(ge=1, le=1440)] = 5,
    group_by: Annotated[
        str | None, Query(pattern=r"^(model|agent_id|project_id)$")
    ] = None,
    model: str | None = None,
    agent_id: str | None = None,
) -> MetricAggregateResponse:
    now = datetime.now(UTC)
    if until is None:
        until = now
    if since is None:
        since = until - timedelta(hours=24)

    overall, by_group = aggregate_metrics(
        session,
        org_id=org.id,
        since=since,
        until=until,
        bucket_minutes=bucket_minutes,
        group_by=group_by,
        filter_model=model,
        filter_agent_id=agent_id,
    )
    return MetricAggregateResponse(
        bucket_size_minutes=bucket_minutes,
        group_by=group_by,
        buckets=overall,
        by_group=by_group,
    )


@router.get(
    "/metrics/prometheus",
    response_class=Response,
    responses={200: {"content": {"text/plain": {}}}},
)
def prometheus_exposition(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> Response:
    """Prometheus text exposition format for the calling org.

    Configure your scraper with the X-API-Key + X-Org-Slug headers (or
    OAuth session). Series exposed: praetor_requests_total,
    praetor_tokens_total, praetor_cost_usd_total,
    praetor_request_duration_ms_summary, praetor_alert_rules,
    praetor_alert_events_total.
    """
    body = render_prometheus(session, org_id=org.id)
    return Response(
        content=body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
