"""Asynchronous audit-chain verification.

Under async-verify ingest, events are accepted fast and land ``verified=False``.
This module is the consumer that verifies chain linkage off the hot path: for
each ``(agent_id, session_id)`` chain it advances the verified prefix in ``seq``
order, flipping events to ``verified=True`` as long as each links to the prior
hash. A gap (the next ``seq`` hasn't arrived yet) simply pauses that chain until
it does; a genuine linkage break (right ``seq``, wrong ``prev_hash``) raises a
tamper finding and stops that chain.

Self-hash integrity is already checked synchronously at ingest, so this pass
only validates the *ordering/linkage* the synchronous path used to enforce
inline — the part that required reading the chain tip under contention.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ephorate_engine.audit_hash import GENESIS_HASH
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    OPEN_FINDING_STATUSES,
    AuditEvent,
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingSource,
)

_TAMPER_RULE = "audit-chain-integrity"


def _chain_tip(
    session: Session, org_id: str, agent_id: str, session_id: str
) -> AuditEvent | None:
    """Latest *verified* event for a chain (its verified tip)."""
    return session.execute(
        select(AuditEvent)
        .where(
            AuditEvent.organization_id == org_id,
            AuditEvent.agent_id == agent_id,
            AuditEvent.session_id == session_id,
            AuditEvent.verified.is_(True),
        )
        .order_by(AuditEvent.seq.desc())
        .limit(1)
    ).scalar_one_or_none()


def _raise_tamper(
    session: Session,
    org_id: str,
    event: AuditEvent,
    expected_prev: str,
    now: datetime,
) -> None:
    """Record (or refresh) a CRITICAL tamper finding for a broken chain link."""
    dedup_key = f"audit-chain:{event.agent_id}:{event.session_id}"
    existing = session.execute(
        select(Finding)
        .where(
            Finding.organization_id == org_id,
            Finding.dedup_key == dedup_key,
            Finding.status.in_(OPEN_FINDING_STATUSES),
        )
        .limit(1)
    ).scalar_one_or_none()
    evidence: dict[str, Any] = {
        "agent_id": event.agent_id,
        "session_id": event.session_id,
        "seq": event.seq,
        "expected_prev_hash": expected_prev,
        "got_prev_hash": event.prev_hash,
        "event_hash": event.hash,
    }
    if existing is not None:
        existing.count += 1
        existing.last_seen = now
        existing.evidence = evidence
        return
    session.add(
        Finding(
            organization_id=org_id,
            rule_id=_TAMPER_RULE,
            title=(
                f"Audit chain break at seq {event.seq} "
                f"(agent {event.agent_id}, session {event.session_id})"
            ),
            severity=FindingSeverity.CRITICAL.value,
            category=FindingCategory.ANOMALY.value,
            source=FindingSource.DETECTION_ENGINE.value,
            impact="major",
            fidelity=1.0,
            agent_id=event.agent_id,
            session_id=event.session_id,
            dedup_key=dedup_key,
            count=1,
            first_seen=now,
            last_seen=now,
            evidence=evidence,
            atlas_technique="AML.T0031",  # Erode ML Model Integrity (closest)
        )
    )


def verify_pending(
    session: Session,
    org_id: str,
    *,
    max_chains: int = 10_000,
    now: datetime | None = None,
) -> dict[str, int]:
    """Advance verification for every chain with unverified events.

    Returns {verified, chains, tampered}. Idempotent and resumable — a gap
    pauses a chain until the missing event arrives; a linkage break flags it.
    """
    now = now or datetime.now(UTC)
    chains = session.execute(
        select(AuditEvent.agent_id, AuditEvent.session_id)
        .where(
            AuditEvent.organization_id == org_id,
            AuditEvent.verified.is_(False),
        )
        .distinct()
        .limit(max_chains)
    ).all()

    verified_count = 0
    tampered = 0
    for agent_id, session_id in chains:
        tip = _chain_tip(session, org_id, agent_id, session_id)
        expected_seq = tip.seq + 1 if tip is not None else 0
        expected_prev = tip.hash if tip is not None else GENESIS_HASH

        pending = session.execute(
            select(AuditEvent)
            .where(
                AuditEvent.organization_id == org_id,
                AuditEvent.agent_id == agent_id,
                AuditEvent.session_id == session_id,
                AuditEvent.verified.is_(False),
            )
            .order_by(AuditEvent.seq.asc())
        ).scalars()

        for ev in pending:
            if ev.seq != expected_seq:
                # The next expected event hasn't arrived yet (out-of-order /
                # in-flight). Pause this chain; a later pass resumes it.
                break
            if ev.prev_hash != expected_prev:
                _raise_tamper(session, org_id, ev, expected_prev, now)
                tampered += 1
                break
            ev.verified = True
            verified_count += 1
            expected_seq += 1
            expected_prev = ev.hash

    session.flush()
    return {
        "verified": verified_count,
        "chains": len(chains),
        "tampered": tampered,
    }


__all__ = ["verify_pending"]
