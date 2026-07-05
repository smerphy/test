"""Background tasks bound to Celery.

In production these run on the Celery worker (`celery -A app.celery_app
worker`). In tests, `PRAETOR_CELERY_TASK_ALWAYS_EAGER=true` (the
default) routes them synchronously, so router code can call `.delay()`
in both environments without branching.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.celery_app import celery_app
from app.db import SessionLocal
from app.models import AlertRule, ComplianceReport, Organization, ThreatFeed
from app.schemas import AuditEventIn, MetricEventIn
from app.services.alerts import evaluate_rule
from app.services.approvals import expire_stale_approvals
from app.services.audit_ingest import ingest_event
from app.services.detections import run_detections
from app.services.forward import forward_finding
from app.services.metrics import ingest_metric
from app.services.notify import deliver_approval_notification
from app.services.report import generate_report
from app.services.retention import apply_retention
from app.services.threat_intel import sync_feed
from app.settings import get_settings


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


@celery_app.task(name="praetor.approvals.expire_stale")
def expire_stale_approvals_task() -> int:
    """Sweep expired pending approvals. Schedule via Celery beat (~every 60s)."""
    with SessionLocal() as session:
        expired = expire_stale_approvals(session)
        session.commit()
    return expired


@celery_app.task(name="praetor.detections.run_all")
def run_detections_task() -> dict[str, int]:
    """Run the detection engine across every org. Schedule via Celery beat."""
    created = updated = quarantined = forwarded = 0
    with SessionLocal() as session:
        org_ids = list(
            session.execute(select(Organization.id)).scalars()
        )
        for org_id in org_ids:
            result = run_detections(session, org_id=org_id)
            created += result["created"]
            updated += result["updated"]
            quarantined += result.get("quarantined", 0)
            # Forward each new finding to the org's SIEM/webhook (best-effort).
            for finding_id in result.get("new_finding_ids", []):
                if forward_finding(session, finding_id):
                    forwarded += 1
        session.commit()
    return {
        "created": created,
        "updated": updated,
        "quarantined": quarantined,
        "forwarded": forwarded,
    }


@celery_app.task(name="praetor.telemetry.apply_retention")
def apply_retention_task() -> dict[str, int]:
    """Roll up + prune aged raw audit events across every org.

    Schedule via Celery beat (daily). No-op unless
    `PRAETOR_AUDIT_RETENTION_DAYS` is set. Loops each org until caught up so a
    large backlog is drained across bounded batches within one run.
    """
    settings = get_settings()
    if settings.audit_retention_days is None:
        return {"rolled": 0, "pruned": 0, "orgs": 0}
    rolled = pruned = orgs = 0
    with SessionLocal() as session:
        org_ids = list(session.execute(select(Organization.id)).scalars())
        for org_id in org_ids:
            orgs += 1
            for _ in range(1000):  # safety bound on batches per org per run
                result = apply_retention(
                    session,
                    org_id=org_id,
                    retention_days=settings.audit_retention_days,
                    batch_size=settings.retention_batch_size,
                )
                rolled += result["rolled"]
                pruned += result["pruned"]
                session.commit()
                if result["caught_up"]:
                    break
    return {"rolled": rolled, "pruned": pruned, "orgs": orgs}


@celery_app.task(name="praetor.threat_intel.sync_due")
def sync_threat_feeds_task() -> dict[str, int]:
    """Sync every enabled remote feed whose refresh interval has elapsed.

    Schedule via Celery beat. Each feed's sync is self-contained and records
    its own error status, so one bad feed can't fail the sweep.
    """
    now = datetime.now(UTC)
    synced = created = updated = errors = 0
    with SessionLocal() as session:
        feeds = list(
            session.execute(
                select(ThreatFeed).where(
                    ThreatFeed.enabled.is_(True),
                    ThreatFeed.url.is_not(None),
                )
            ).scalars()
        )
        for feed in feeds:
            due_at = (
                feed.last_synced_at + timedelta(minutes=feed.refresh_minutes)
                if feed.last_synced_at is not None
                else None
            )
            # last_synced_at is stored tz-aware in Postgres but naive under
            # SQLite; normalize both sides to naive-UTC for comparison.
            if due_at is not None:
                due_cmp = (
                    due_at.replace(tzinfo=None) if due_at.tzinfo else due_at
                )
                if due_cmp > now.replace(tzinfo=None):
                    continue
            result = sync_feed(session, feed, now=now)
            synced += 1
            created += result.get("created", 0)
            updated += result.get("updated", 0)
            if result.get("status") == "error":
                errors += 1
        session.commit()
    return {
        "feeds_synced": synced,
        "created": created,
        "updated": updated,
        "errors": errors,
    }


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
    "apply_retention_task",
    "evaluate_all_alerts_task",
    "expire_stale_approvals_task",
    "generate_report_task",
    "notify_approval_task",
    "process_audit_batch_task",
    "process_metric_batch_task",
    "run_detections_task",
    "sync_threat_feeds_task",
]
