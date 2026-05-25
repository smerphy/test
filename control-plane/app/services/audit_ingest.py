"""Audit event ingestion with chain verification.

For each event we verify it chains correctly off the latest stored event
from the same (organization, agent, session). If the chain breaks
(prev_hash mismatch or recomputed hash mismatch), we reject the event
and surface the error to the caller — never silently accept tampered
data.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.schemas import AuditEventIn

GENESIS_HASH = "0" * 64


def _canonical_hash(payload: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _verify_hash(event: AuditEventIn) -> None:
    # Use the same wire-bytes path as the SDK's verify_chain so that
    # any conformant writer's events ingest cleanly.
    body = event.model_dump(mode="json", exclude={"hash"})
    expected = _canonical_hash(body)
    if expected != event.hash:
        raise ValueError(
            f"hash mismatch (computed {expected}, stored {event.hash})"
        )


def _latest_event(
    session: Session, *, org_id: str, agent_id: str, session_id: str
) -> AuditEvent | None:
    stmt = (
        select(AuditEvent)
        .where(
            AuditEvent.organization_id == org_id,
            AuditEvent.agent_id == agent_id,
            AuditEvent.session_id == session_id,
        )
        .order_by(AuditEvent.seq.desc())
        .limit(1)
    )
    return session.execute(stmt).scalar_one_or_none()


def _by_hash(
    session: Session, *, org_id: str, hash_: str
) -> AuditEvent | None:
    stmt = select(AuditEvent).where(
        AuditEvent.organization_id == org_id, AuditEvent.hash == hash_
    )
    return session.execute(stmt).scalar_one_or_none()


def ingest_event(
    session: Session, *, org_id: str, event: AuditEventIn
) -> AuditEvent:
    _verify_hash(event)

    # Idempotency: at-least-once shippers may re-send an event whose
    # ack was lost. Detect by hash and return the existing row.
    existing = _by_hash(session, org_id=org_id, hash_=event.hash)
    if existing is not None:
        return existing

    latest = _latest_event(
        session,
        org_id=org_id,
        agent_id=event.agent_id,
        session_id=event.session_id,
    )
    if latest is None:
        expected_prev = GENESIS_HASH
        expected_seq = 0
    else:
        expected_prev = latest.hash
        expected_seq = latest.seq + 1

    if event.prev_hash != expected_prev:
        raise ValueError(
            f"prev_hash mismatch for (agent={event.agent_id}, "
            f"session={event.session_id}): expected {expected_prev}, got {event.prev_hash}"
        )
    if event.seq != expected_seq:
        raise ValueError(
            f"seq mismatch: expected {expected_seq}, got {event.seq}"
        )

    row = AuditEvent(
        organization_id=org_id,
        seq=event.seq,
        timestamp=event.timestamp,
        agent_id=event.agent_id,
        session_id=event.session_id,
        tool_name=event.tool_name,
        tool_use_id=event.tool_use_id,
        tool_arguments=event.tool_arguments,
        decision=event.decision,
        reason=event.reason,
        matched_policy_id=event.matched_policy_id,
        suggested_transform=event.suggested_transform,
        context=event.context,
        evaluator_version=event.evaluator_version,
        prev_hash=event.prev_hash,
        hash=event.hash,
    )
    session.add(row)
    session.flush()
    return row


__all__ = ["GENESIS_HASH", "ingest_event"]
