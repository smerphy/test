"""Celery app. Tasks are defined in `app.workers.tasks` and registered
here by include path. Production uses Redis; tests use eager mode
(no broker required)."""

from __future__ import annotations

from celery import Celery

from app.settings import get_settings

_settings = get_settings()

celery_app = Celery(
    "praetor",
    broker=_settings.celery_broker_url,
    backend=_settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_always_eager=_settings.celery_task_always_eager,
    task_eager_propagates=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    worker_hijack_root_logger=False,
)

# Periodic tasks — active when `celery -A app.celery_app beat` runs (no effect
# on eager mode / tests). Both sweeps are idempotent and cheap.
celery_app.conf.beat_schedule = {
    "evaluate-alerts": {
        "task": "praetor.alerts.evaluate_all",
        "schedule": 60.0,
    },
    "expire-stale-approvals": {
        "task": "praetor.approvals.expire_stale",
        "schedule": 60.0,
    },
    "run-detections": {
        "task": "praetor.detections.run_all",
        "schedule": 120.0,
    },
    "sync-threat-feeds": {
        "task": "praetor.threat_intel.sync_due",
        "schedule": 300.0,
    },
    "apply-retention": {
        "task": "praetor.telemetry.apply_retention",
        "schedule": 86400.0,  # daily
    },
    "verify-audit-chains": {
        "task": "praetor.audit.verify_chains",
        "schedule": 30.0,  # async-verify: flip verified / flag tamper
    },
    "archive-audit": {
        "task": "praetor.audit.archive",
        "schedule": 300.0,  # authoritative cold-tier archival
    },
    "consume-log": {
        "task": "praetor.log.consume",
        "schedule": 10.0,  # drain the event log into hot + analytics stores
    },
    "ueba-rebuild-baselines": {
        "task": "praetor.ueba.rebuild_baselines",
        "schedule": 86400.0,  # daily behavioral-baseline refresh
    },
    "ueba-detect-drift": {
        "task": "praetor.ueba.detect_drift",
        "schedule": 300.0,  # behavioral drift -> findings
    },
    "ai-sweep-findings": {
        "task": "praetor.ai.sweep_findings",
        "schedule": 3600.0,  # hourly proactive hunt (AI-enabled orgs only)
    },
    "anchor-audit": {
        "task": "praetor.audit.anchor_all",
        "schedule": 3600.0,  # hourly immutable anchor of the audit chain heads
    },
}


__all__ = ["celery_app"]
