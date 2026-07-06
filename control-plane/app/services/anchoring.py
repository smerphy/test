"""Compute, persist, publish, and verify audit anchors.

An anchor snapshots the head of every (agent, session) audit chain and a root
over those heads, chained to the prior anchor, and publishes it to the cold
archive (object storage). Verification re-derives the heads from the current
database and compares to a stored anchor: any alteration of an anchored event
shows up as a head mismatch.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditAnchor, AuditEvent, Organization
from app.services.event_store import archive_events

_GENESIS = "0" * 64
_MAX_EVENTS = 500_000


def _chain_heads(session: Session, org_id: str) -> tuple[list[dict[str, Any]], int]:
    """Head {agent, session, seq, hash} per chain + total event count."""
    rows = session.execute(
        select(
            AuditEvent.agent_id,
            AuditEvent.session_id,
            AuditEvent.seq,
            AuditEvent.hash,
        )
        .where(AuditEvent.organization_id == org_id)
        .limit(_MAX_EVENTS)
    ).all()
    heads: dict[tuple[str, str], tuple[int, str]] = {}
    for agent_id, session_id, seq, h in rows:
        key = (agent_id, session_id)
        cur = heads.get(key)
        if cur is None or seq > cur[0]:
            heads[key] = (seq, h)
    chains = [
        {"agent": a, "session": s, "seq": seq, "hash": h}
        for (a, s), (seq, h) in sorted(heads.items())
    ]
    return chains, len(rows)


def _root(chains: list[dict[str, Any]]) -> str:
    lines = "\n".join(
        f"{c['agent']}|{c['session']}|{c['seq']}|{c['hash']}"
        for c in sorted(chains, key=lambda c: (c["agent"], c["session"]))
    )
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def _anchor_hash(
    org_id: str, root: str, chain_count: int, event_count: int, prev: str
) -> str:
    body = f"{org_id}|{root}|{chain_count}|{event_count}|{prev}"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _latest(session: Session, org_id: str) -> AuditAnchor | None:
    return session.execute(
        select(AuditAnchor)
        .where(AuditAnchor.organization_id == org_id)
        .order_by(AuditAnchor.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def create_anchor(session: Session, org: Organization) -> AuditAnchor:
    """Snapshot the chain heads, chain to the prior anchor, persist + publish."""
    chains, event_count = _chain_heads(session, org.id)
    root = _root(chains)
    prev = _latest(session, org.id)
    prev_hash = prev.anchor_hash if prev is not None else _GENESIS
    anchor_hash = _anchor_hash(org.id, root, len(chains), event_count, prev_hash)

    anchor = AuditAnchor(
        organization_id=org.id,
        chain_count=len(chains),
        event_count=event_count,
        root=root,
        prev_anchor_hash=prev_hash,
        anchor_hash=anchor_hash,
        chains=chains,
    )
    session.add(anchor)
    session.flush()

    # Publish to the cold archive (object-store-ready) so the anchor survives a
    # DB compromise. No-op unless PRAETOR_EVENT_ARCHIVE_DIR is configured.
    published = archive_events(
        "audit-anchor",
        org.id,
        [
            {
                "anchor_hash": anchor_hash,
                "prev_anchor_hash": prev_hash,
                "root": root,
                "chain_count": len(chains),
                "event_count": event_count,
                "created_at": anchor.created_at.isoformat(),
                "chains": chains,
            }
        ],
    )
    if published:
        anchor.published_to = "archive"
    session.flush()
    return anchor


def verify_latest(session: Session, org_id: str) -> dict[str, Any]:
    """Re-derive current heads and check them against the latest anchor."""
    anchor = _latest(session, org_id)
    if anchor is None:
        return {"anchored": False, "tampered": False, "mismatches": []}

    mismatches: list[dict[str, Any]] = []
    for c in anchor.chains:
        row = session.execute(
            select(AuditEvent.hash).where(
                AuditEvent.organization_id == org_id,
                AuditEvent.agent_id == c["agent"],
                AuditEvent.session_id == c["session"],
                AuditEvent.seq == c["seq"],
            )
        ).scalar_one_or_none()
        if row is None:
            mismatches.append({**c, "reason": "missing"})
        elif row != c["hash"]:
            mismatches.append({**c, "reason": "hash_mismatch", "found": row})

    return {
        "anchored": True,
        "anchor_hash": anchor.anchor_hash,
        "anchored_at": anchor.created_at.isoformat(),
        "chains_checked": len(anchor.chains),
        "tampered": bool(mismatches),
        "mismatches": mismatches[:50],
    }


__all__ = ["create_anchor", "verify_latest"]
