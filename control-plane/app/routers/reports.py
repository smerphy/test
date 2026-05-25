"""Compliance report generation."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.models import ComplianceReport, Organization, ReportStatus
from app.schemas import ComplianceReportIn, ComplianceReportOut
from app.services.report import generate_report

router = APIRouter(tags=["reports"])


@router.post(
    "/reports/compliance",
    response_model=ComplianceReportOut,
    status_code=status.HTTP_201_CREATED,
)
def request_report(
    body: ComplianceReportIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> ComplianceReport:
    if body.period_end <= body.period_start:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="period_end must be after period_start",
        )
    report = ComplianceReport(
        organization_id=org.id,
        framework=body.framework,
        period_start=body.period_start,
        period_end=body.period_end,
        status=ReportStatus.PENDING,
    )
    session.add(report)
    session.flush()

    # MVP: synchronous generation. Production: enqueue Celery task here
    # and let `app.workers.reports.generate_report_task` do the work.
    generate_report(session, report)
    session.flush()
    return report


@router.get("/reports/compliance", response_model=list[ComplianceReportOut])
def list_reports(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[ComplianceReport]:
    stmt = (
        select(ComplianceReport)
        .where(ComplianceReport.organization_id == org.id)
        .order_by(ComplianceReport.created_at.desc())
    )
    return list(session.execute(stmt).scalars().all())


@router.get(
    "/reports/compliance/{report_id}", response_model=ComplianceReportOut
)
def get_report(
    report_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> ComplianceReport:
    report = session.get(ComplianceReport, report_id)
    if report is None or report.organization_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="report not found")
    return report
