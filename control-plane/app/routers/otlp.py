"""OTLP/HTTP receiver — the OpenTelemetry collector tier's ingest endpoint.

A standard OTel Collector exports batched agent LLM telemetry here; we translate
it to MetricEvents and feed the same ingest path as the native SDK (through the
event log when log-centric ingest is on, else inline). This lets teams stand up
an OTel Collector in front of their fleet for batching/backpressure/fan-out and
point its OTLP exporter at Ephorate.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.models import Organization, Role
from app.services.log_pipeline import publish_metric
from app.services.metrics import ingest_metric
from app.services.otlp import parse_metrics
from app.services.ratelimit import rate_limit
from app.settings import Settings, get_settings

router = APIRouter(tags=["otlp"])


@router.post("/otlp/v1/metrics")
def receive_metrics(
    body: dict[str, Any],
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    _p: Principal = Depends(require_role(Role.ANALYST)),
    _rl: None = Depends(rate_limit("ingest")),
) -> dict[str, int]:
    """Accept an OTLP/HTTP metrics export (GenAI semantic conventions) and
    ingest the per-call data points as MetricEvents."""
    events = parse_metrics(body)
    if not events:
        return {"accepted": 0, "rejected": 0}
    if settings.ingest_via_log:
        return {"accepted": publish_metric(org.id, events), "rejected": 0}
    accepted = 0
    for ev in events:
        try:
            ingest_metric(session, org_id=org.id, event=ev)
            accepted += 1
        except ValueError:
            pass
    return {"accepted": accepted, "rejected": len(events) - accepted}
