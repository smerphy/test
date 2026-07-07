"""Celery app. Tasks are defined in `app.workers.tasks` and registered
here by include path. Production uses Redis; tests use eager mode
(no broker required)."""

from __future__ import annotations

from celery import Celery

from app.settings import get_settings

_settings = get_settings()

celery_app = Celery(
    "ephorate",
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
        "task": "ephorate.alerts.evaluate_all",
        "schedule": 60.0,
    },
    "expire-stale-approvals": {
        "task": "ephorate.approvals.expire_stale",
        "schedule": 60.0,
    },
    "run-detections": {
        "task": "ephorate.detections.run_all",
        "schedule": 120.0,
    },
    "sync-threat-feeds": {
        "task": "ephorate.threat_intel.sync_due",
        "schedule": 300.0,
    },
    "apply-retention": {
        "task": "ephorate.telemetry.apply_retention",
        "schedule": 86400.0,  # daily
    },
    "verify-audit-chains": {
        "task": "ephorate.audit.verify_chains",
        "schedule": 30.0,  # async-verify: flip verified / flag tamper
    },
    "archive-audit": {
        "task": "ephorate.audit.archive",
        "schedule": 300.0,  # authoritative cold-tier archival
    },
    "consume-log": {
        "task": "ephorate.log.consume",
        "schedule": 10.0,  # drain the event log into hot + analytics stores
    },
    "ueba-rebuild-baselines": {
        "task": "ephorate.ueba.rebuild_baselines",
        "schedule": 86400.0,  # daily behavioral-baseline refresh
    },
    "ueba-detect-drift": {
        "task": "ephorate.ueba.detect_drift",
        "schedule": 300.0,  # behavioral drift -> findings
    },
    "ai-sweep-findings": {
        "task": "ephorate.ai.sweep_findings",
        "schedule": 3600.0,  # hourly proactive hunt (AI-enabled orgs only)
    },
    "anchor-audit": {
        "task": "ephorate.audit.anchor_all",
        "schedule": 3600.0,  # hourly immutable anchor of the audit chain heads
    },
}


__all__ = ["celery_app"]
