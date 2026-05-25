"""Compliance report generation.

Aggregates audit events in the report's period against a framework's
controls and emits a summary suitable for downstream PDF rendering.
For MVP we ship the JSON summary; the PDF renderer is a Phase 4 / 5
deliverable.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, ComplianceReport, ReportStatus

# Minimal control mapping. Real bundles in engine/bundles/ will supply
# the policy → control mapping; for MVP we surface decision-rate
# aggregates that map cleanly to the most-asked-about controls.
_FRAMEWORK_CONTROLS: Mapping[str, list[str]] = {
    "nist_ai_rmf": ["GOVERN-1.1", "GOVERN-1.2", "MANAGE-2.1", "MEASURE-2.7"],
    "iso_42001": ["A.5.2", "A.6.1.3", "A.8.4"],
    "eu_ai_act": ["Article-14", "Article-15", "Article-16"],
}


def _decision_counts(
    session: Session, *, org_id: str, period_start: object, period_end: object
) -> dict[str, int]:
    stmt = (
        select(AuditEvent.decision, func.count())
        .where(
            AuditEvent.organization_id == org_id,
            AuditEvent.timestamp >= period_start,
            AuditEvent.timestamp <= period_end,
        )
        .group_by(AuditEvent.decision)
    )
    return {row[0]: row[1] for row in session.execute(stmt).all()}


def generate_report(session: Session, report: ComplianceReport) -> None:
    """Materialize the report's summary in place."""
    report.status = ReportStatus.GENERATING
    try:
        controls = _FRAMEWORK_CONTROLS.get(report.framework)
        if controls is None:
            raise ValueError(f"unsupported framework: {report.framework}")

        counts = _decision_counts(
            session,
            org_id=report.organization_id,
            period_start=report.period_start,
            period_end=report.period_end,
        )
        total = sum(counts.values())
        deny_total = counts.get("deny", 0)
        approval_total = counts.get("require_approval", 0)

        summary: dict[str, Any] = {
            "framework": report.framework,
            "period_start": report.period_start.isoformat(),
            "period_end": report.period_end.isoformat(),
            "controls": controls,
            "decision_counts": counts,
            "total_evaluations": total,
            "deny_rate": (deny_total / total) if total else 0.0,
            "approval_rate": (approval_total / total) if total else 0.0,
        }

        report.summary = summary
        report.status = ReportStatus.COMPLETE
    except Exception as exc:
        report.status = ReportStatus.FAILED
        report.error = str(exc)


__all__ = ["generate_report"]
