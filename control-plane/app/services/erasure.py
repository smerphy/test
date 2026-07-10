"""Right-to-erasure: scrub a data subject's identifier from stored records.

Replaces every occurrence of a subject string (an email, name, user id, …) with
an ``[ERASED]`` marker across the mutable stores — findings and approval
requests. Audit events are covered by the tamper-evident hash chain and are NOT
mutated here (scrubbing them would break verification); the erasure result
reports how many audit rows still reference the subject so they can be handled
by client-side pre-hash redaction / chain rotation.

Supports a dry run so an operator can preview the blast radius before erasing.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ApprovalRequest, AuditEvent, Finding
from app.services.pii import scrub_subject


def erase_subject(
    session: Session, org_id: str, subject: str, *, dry_run: bool = False
) -> dict[str, Any]:
    """Scrub `subject` from findings + approvals for one org.

    Returns per-store match/erasure counts plus the audit-event reference count
    that must be handled out-of-band.
    """
    subject = subject.strip()
    result: dict[str, Any] = {
        "subject": subject,
        "dry_run": dry_run,
        "findings_scrubbed": 0,
        "approvals_scrubbed": 0,
        "occurrences": 0,
        "audit_events_referencing": 0,
    }
    if not subject:
        return result

    findings = session.execute(
        select(Finding).where(Finding.organization_id == org_id)
    ).scalars()
    for f in findings:
        count = 0
        new_title, c1 = scrub_subject(f.title, subject)
        new_evidence, c2 = scrub_subject(f.evidence, subject)
        new_note, c3 = scrub_subject(f.note or "", subject)
        count = c1 + c2 + c3
        if count:
            result["findings_scrubbed"] += 1
            result["occurrences"] += count
            if not dry_run:
                f.title = new_title
                f.evidence = new_evidence
                if f.note:
                    f.note = new_note

    approvals = session.execute(
        select(ApprovalRequest).where(ApprovalRequest.organization_id == org_id)
    ).scalars()
    for a in approvals:
        new_args, c1 = scrub_subject(a.tool_arguments, subject)
        new_reason, c2 = scrub_subject(a.reason, subject)
        count = c1 + c2
        if count:
            result["approvals_scrubbed"] += 1
            result["occurrences"] += count
            if not dry_run:
                a.tool_arguments = new_args
                a.reason = new_reason

    # Audit events are immutable (hash-chained) — report references, don't
    # mutate. JSON containment SQL differs across engines, so scan every row.
    # Stream in server-side chunks (yield_per) rather than capping the scan: a
    # fixed LIMIT silently under-reported the blast radius for orgs above the
    # cap, telling an operator fewer immutable records referenced the subject
    # than actually do.
    matched = 0
    stream = (
        session.execute(
            select(AuditEvent.tool_arguments, AuditEvent.reason)
            .where(AuditEvent.organization_id == org_id)
            .execution_options(stream_results=True)
        )
        .yield_per(2_000)
    )
    for args, reason in stream:
        _, c1 = scrub_subject(args, subject)
        _, c2 = scrub_subject(reason or "", subject)
        if c1 or c2:
            matched += 1
    result["audit_events_referencing"] = matched

    if not dry_run:
        session.flush()
    return result


__all__ = ["erase_subject"]
