"""Compliance report PDF rendering.

Pure-Python via reportlab — no system deps (LaTeX, Chrome, wkhtmltopdf).
The PDF mirrors the JSON summary: title, period, decision counts,
deny / approval rates, and the framework controls the bundle claims to
satisfy.
"""

from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models import ComplianceReport

_FRAMEWORK_TITLES = {
    "nist_ai_rmf": "NIST AI Risk Management Framework (AI RMF 1.0)",
    "iso_42001": "ISO/IEC 42001:2023 — AI Management System",
    "eu_ai_act": "EU AI Act — Human Oversight (Article 14)",
}


def render_report_pdf(report: ComplianceReport) -> bytes:
    if report.summary is None:
        raise ValueError(
            f"report {report.id} has no summary (status={report.status.value})"
        )

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=f"Praetor compliance report — {report.framework}",
    )
    styles = getSampleStyleSheet()
    story = []

    story.append(
        Paragraph(
            _FRAMEWORK_TITLES.get(report.framework, report.framework),
            styles["Title"],
        )
    )
    story.append(Spacer(1, 0.15 * inch))

    period_line = (
        f"Period: {report.period_start.isoformat()} → "
        f"{report.period_end.isoformat()}"
    )
    story.append(Paragraph(period_line, styles["Normal"]))
    story.append(
        Paragraph(
            f"Generated: {report.created_at.isoformat()}", styles["Normal"]
        )
    )
    story.append(Spacer(1, 0.3 * inch))

    summary = report.summary
    counts = summary["decision_counts"]
    total = summary["total_evaluations"]

    story.append(Paragraph("Summary", styles["Heading2"]))
    summary_rows = [
        ["Metric", "Value"],
        ["Total evaluations", f"{total}"],
        ["Allow", f"{counts.get('allow', 0)}"],
        ["Deny", f"{counts.get('deny', 0)}"],
        ["Transform", f"{counts.get('transform', 0)}"],
        ["Require approval", f"{counts.get('require_approval', 0)}"],
        ["Deny rate", f"{summary['deny_rate'] * 100:.2f}%"],
        ["Approval rate", f"{summary['approval_rate'] * 100:.2f}%"],
    ]
    table = Table(summary_rows, colWidths=[3 * inch, 2 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("Controls covered", styles["Heading2"]))
    for control in summary["controls"]:
        story.append(Paragraph(f"• {control}", styles["Normal"]))

    story.append(Spacer(1, 0.3 * inch))
    story.append(
        Paragraph(
            "<i>This report is generated from Praetor audit events. Each "
            "tool-call decision is signed and chained; the events backing "
            "this summary can be re-verified via "
            "<font face='Courier'>praetor.verify_chain</font>.</i>",
            styles["Normal"],
        )
    )

    doc.build(story)
    return buffer.getvalue()


__all__ = ["render_report_pdf"]
