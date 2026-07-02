"""Background tasks bound to Celery.

In production these run on the Celery worker (`celery -A app.celery_app
worker`). In tests, `PRAETOR_CELERY_TASK_ALWAYS_EAGER=true` (the
default) routes them synchronously, so router code can call `.delay()`
in both environments without branching.
"""

from __future__ import annotations

from sqlalchemy import select

from app.celery_app import celery_app
from app.db import SessionLocal
from app.models import AlertRule, ComplianceReport
from app.schemas import AuditEventIn, MetricEventIn
from app.services.alerts import evaluate_rule
from app.services.audit_ingest import ingest_event
from app.services.metrics import ingest_metric
from app.services.notify import deliver_approval_notification
from app.services.report import generate_report


@celery_app.task(name="praetor.audit.process_batch")
def process_audit_batch_task(
    org_id: str, events: list[dict[str, object]]
) -> dict[str, int]:
    """Bulk-ingest a batch of audit events. Returns {accepted, rejected}."""
    accepted = 0
    rejected = 0
    with SessionLocal() as session:
        for raw in events:
            try:
                ingest_event(
                    session,
                    org_id=org_id,
                    event=AuditEventIn.model_validate(raw),
                )
                accepted += 1
            except Exception:
                rejected += 1
        session.commit()
    return {"accepted": accepted, "rejected": rejected}


@celery_app.task(name="praetor.metrics.process_batch")
def process_metric_batch_task(
    org_id: str, events: list[dict[str, object]]
) -> dict[str, int]:
    """Bulk-ingest a batch of Claude API metrics. Returns {accepted, rejected}."""
    accepted = 0
    rejected = 0
    with SessionLocal() as session:
        for raw in events:
            try:
                ingest_metric(
                    session,
                    org_id=org_id,
                    event=MetricEventIn.model_validate(raw),
                )
                accepted += 1
            except Exception:
                rejected += 1
        session.commit()
    return {"accepted": accepted, "rejected": rejected}


@celery_app.task(name="praetor.reports.generate")
def generate_report_task(report_id: str) -> None:
    """Generate a compliance report by id. Idempotent for the COMPLETE case."""
    with SessionLocal() as session:
        report = session.get(ComplianceReport, report_id)
        if report is None:
            return
        generate_report(session, report)
        session.commit()


@celery_app.task(name="praetor.approvals.notify")
def notify_approval_task(approval_id: str) -> bool:
    """Post a pending-approval notification to the org webhook. Best-effort."""
    with SessionLocal() as session:
        return deliver_approval_notification(session, approval_id)


@celery_app.task(name="praetor.alerts.evaluate_all")
def evaluate_all_alerts_task() -> dict[str, int]:
    """Evaluate every enabled alert rule across every org.

    Production deployment: schedule via Celery beat (every 60s).
    Returns per-rule firing counts for observability.
    """
    fired_total = 0
    rules_checked = 0
    with SessionLocal() as session:
        rules = list(
            session.execute(
                select(AlertRule).where(AlertRule.enabled == True)  # noqa: E712
            ).scalars()
        )
        for rule in rules:
            rules_checked += 1
            fired = evaluate_rule(session, rule)
            fired_total += len(fired)
        session.commit()
    return {"rules_checked": rules_checked, "alerts_fired": fired_total}


__all__ = [
    "evaluate_all_alerts_task",
    "generate_report_task",
    "notify_approval_task",
    "process_audit_batch_task",
    "process_metric_batch_task",
]
