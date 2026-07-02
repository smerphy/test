"""Compliance report generation."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import current_org
from app.db import get_session
from app.models import ComplianceReport, Organization, ReportStatus
from app.schemas import ComplianceReportIn, ComplianceReportOut
from app.services.pdf import render_report_pdf
from app.workers.tasks import generate_report_task

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
    # Commit so the worker (which opens its own session) can see the row,
    # then enqueue. Eager mode (tests + dev) runs the task inline.
    session.commit()
    generate_report_task.delay(report.id)
    session.refresh(report)
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


@router.get("/reports/compliance/{report_id}/pdf")
def get_report_pdf(
    report_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> Response:
    report = session.get(ComplianceReport, report_id)
    if report is None or report.organization_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="report not found")
    if report.status is not ReportStatus.COMPLETE:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"report not ready (status={report.status.value})",
        )
    pdf = render_report_pdf(report)
    filename = f"praetor-{report.framework}-{report.id[:8]}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
