"""Task definitions. Plain functions; bind to Celery in deployment."""

from __future__ import annotations

from app.db import SessionLocal
from app.models import ComplianceReport
from app.schemas import AuditEventIn
from app.services.audit_ingest import ingest_event
from app.services.report import generate_report


def process_audit_batch_task(
    org_id: str, events: list[dict[str, object]]
) -> dict[str, int]:
    """Bulk-ingest a batch of events. Returns {accepted, rejected}."""
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


def generate_report_task(report_id: str) -> None:
    """Generate a compliance report by id. Idempotent for the COMPLETE case."""
    with SessionLocal() as session:
        report = session.get(ComplianceReport, report_id)
        if report is None:
            return
        generate_report(session, report)
        session.commit()


__all__ = ["generate_report_task", "process_audit_batch_task"]
