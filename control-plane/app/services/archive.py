"""Authoritative cold-tier archival + replay for audit events.

Rather than best-effort archiving from the ingest request (which diverges from
the hot store if the write fails or the process dies mid-request), archival is
driven from committed rows by a cursor: :func:`archive_pending` selects events
whose ``archived_at IS NULL``, writes them to the cold tier, and only then
stamps ``archived_at``. A crash between write and stamp re-writes on the next
pass — the cold tier is at-least-once and deduped by ``hash`` on replay, so it
never silently loses an event.

Because the cold tier is written from committed state, it is authoritative:
:func:`replay_archive` reads it back and re-ingests (idempotent on
``(org, hash)``), so the hot Postgres store is a rebuildable materialized view.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.schemas import AuditEventIn
from app.services.audit_ingest import ingest_event
from app.services.event_store import archive_events, get_event_sink, read_archive

_KIND = "audit"


def _event_record(row: AuditEvent) -> dict[str, Any]:
    """Serialize an audit row into its canonical (hashed-body + hash) shape —
    exactly what :class:`AuditEventIn` accepts, so it round-trips on replay.

    The timestamp is emitted UTC-aware: SQLite drops the offset on write, so a
    naive round-tripped value must be re-stamped UTC to reproduce the exact
    string the SDK hashed (else replay's hash check would reject it)."""
    ts = row.timestamp if row.timestamp.tzinfo else row.timestamp.replace(tzinfo=UTC)
    return {
        "seq": row.seq,
        "timestamp": ts.isoformat(),
        "agent_id": row.agent_id,
        "session_id": row.session_id,
        "tool_name": row.tool_name,
        "tool_use_id": row.tool_use_id,
        "tool_arguments": row.tool_arguments,
        "decision": row.decision,
        "reason": row.reason,
        "matched_policy_id": row.matched_policy_id,
        "suggested_transform": row.suggested_transform,
        "context": row.context,
        "evaluator_version": row.evaluator_version,
        "prev_hash": row.prev_hash,
        "hash": row.hash,
    }


def archive_pending(
    session: Session,
    org_id: str,
    *,
    batch_size: int = 10_000,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Write not-yet-archived audit events to the cold tier and stamp them.

    Returns {archived, caught_up, enabled}. A no-op when archival is disabled
    (rows are left unstamped so they archive once a cold tier is configured).
    """
    if not get_event_sink().enabled:
        return {"archived": 0, "caught_up": True, "enabled": False}
    now = now or datetime.now(UTC)
    rows = list(
        session.execute(
            select(AuditEvent)
            .where(
                AuditEvent.organization_id == org_id,
                AuditEvent.archived_at.is_(None),
            )
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            .limit(batch_size)
        ).scalars()
    )
    if not rows:
        return {"archived": 0, "caught_up": True, "enabled": True}

    written = archive_events(_KIND, org_id, [_event_record(r) for r in rows])
    if written:
        # Stamp only after a successful cold-tier write.
        for r in rows:
            r.archived_at = now
        session.flush()
    return {
        "archived": len(rows) if written else 0,
        "caught_up": len(rows) < batch_size,
        "enabled": True,
    }


def replay_archive(session: Session, org_id: str) -> dict[str, int]:
    """Re-ingest the cold archive into the hot store to rebuild it.

    Idempotent: events already present (by ``(org, hash)``) are skipped, so
    replay is safe to run against a partially- or fully-populated hot store.
    Returns {read, reingested, skipped}.
    """
    read = reingested = skipped = 0
    for rec in read_archive(_KIND, org_id):
        read += 1
        hash_ = rec.get("hash")
        if hash_ and session.execute(
            select(AuditEvent.id).where(
                AuditEvent.organization_id == org_id,
                AuditEvent.hash == hash_,
            )
        ).first():
            skipped += 1
            continue
        try:
            ingest_event(
                session, org_id=org_id, event=AuditEventIn.model_validate(rec)
            )
            reingested += 1
        except Exception:
            # A malformed or non-chaining archived record must not abort the
            # whole replay; skip it and continue.
            skipped += 1
    session.flush()
    return {"read": read, "reingested": reingested, "skipped": skipped}


__all__ = ["archive_pending", "replay_archive"]
