"""Verify tasks are bound to Celery and run end-to-end in eager mode."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.celery_app import celery_app
from app.models import ApprovalRequest, AuditEvent, ComplianceReport, Organization, ReportStatus
from app.schemas import AuditEventIn
from app.workers.tasks import generate_report_task, process_audit_batch_task


def test_celery_app_eager_in_tests() -> None:
    assert celery_app.conf.task_always_eager is True


def test_celery_tasks_are_registered() -> None:
    registered = set(celery_app.tasks.keys())
    assert "ephorate.audit.process_batch" in registered
    assert "ephorate.reports.generate" in registered


def test_generate_report_task_runs_via_delay(
    session: Session, org: Organization
) -> None:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    # Seed one event so the report has something to summarize.
    session.add(
        AuditEvent(
            organization_id=org.id,
            seq=0,
            timestamp=base,
            agent_id="a",
            session_id="s",
            tool_name="http.get",
            tool_arguments={},
            decision="allow",
            reason="x",
            matched_policy_id="p1",
            context={},
            evaluator_version="0.1.0",
            prev_hash="0" * 64,
            hash="f" * 64,
        )
    )
    report = ComplianceReport(
        organization_id=org.id,
        framework="nist_ai_rmf",
        period_start=base,
        period_end=base + timedelta(hours=1),
        status=ReportStatus.PENDING,
    )
    session.add(report)
    session.commit()

    # Eager mode: .delay() runs inline.
    generate_report_task.delay(report.id)

    session.refresh(report)
    assert report.status is ReportStatus.COMPLETE
    assert report.summary is not None


def test_process_audit_batch_task_counts_accepted_and_rejected(
    org: Organization,
) -> None:
    good = AuditEventIn(
        seq=0,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        agent_id="a",
        session_id="s",
        tool_name="t",
        tool_arguments={},
        decision="allow",
        reason="ok",
        matched_policy_id="p1",
        suggested_transform=None,
        context={},
        evaluator_version="0.1.0",
        prev_hash="0" * 64,
        hash="0" * 64,
    )
    # Compute correct hash via the shared canonical helper.
    from ephorate_engine.audit_hash import compute_hash

    body = good.model_dump(mode="json", exclude={"hash"})
    good_dict = good.model_dump(mode="json")
    good_dict["hash"] = compute_hash(body)

    bad_dict = {**good_dict, "hash": "0" * 64}  # tampered hash

    result = process_audit_batch_task.delay(
        org.id, [good_dict, bad_dict]
    ).get()
    assert result == {"accepted": 1, "rejected": 1}


def test_approval_models_still_work_after_celery_wiring(
    session: Session, org: Organization
) -> None:
    # Sanity: importing celery_app shouldn't have broken anything else.
    a = ApprovalRequest(
        organization_id=org.id,
        agent_id="a",
        session_id="s",
        tool_name="t",
        tool_arguments={},
        reason="x",
    )
    session.add(a)
    session.commit()
    assert a.id is not None
