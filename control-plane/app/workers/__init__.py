"""Background workers.

For MVP these are plain functions invoked synchronously by the routers.
Wire to Celery (or RQ / arq) by importing and decorating in a separate
celery_app.py module that the worker process loads.
"""

from app.workers.tasks import generate_report_task, process_audit_batch_task

__all__ = ["generate_report_task", "process_audit_batch_task"]
