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


__all__ = ["celery_app"]
