"""Global kill-switch + break-glass exceptions.

Engaging the kill-switch sets ``Organization.halt_all``; the quarantine check
then treats every agent as isolated so SDK-driven traffic is denied inline —
except agents with an active break-glass grant, which remain able to operate
(e.g. a remediation agent) while everything else is frozen.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import BreakGlassGrant, Organization


def engage(session: Session, org: Organization, *, by: str | None = None) -> None:
    org.halt_all = True
    session.flush()


def release(session: Session, org: Organization) -> None:
    org.halt_all = False
    session.flush()


def grant_break_glass(
    session: Session,
    org: Organization,
    *,
    agent_id: str,
    reason: str,
    minutes: int,
    by: str | None = None,
    now: datetime | None = None,
) -> BreakGlassGrant:
    now = now or datetime.now(UTC)
    grant = BreakGlassGrant(
        organization_id=org.id,
        agent_id=agent_id,
        reason=reason,
        granted_by=by,
        expires_at=now + timedelta(minutes=minutes),
    )
    session.add(grant)
    session.flush()
    return grant


def active_break_glass(
    session: Session,
    org_id: str,
    *,
    agent_id: str,
    now: datetime | None = None,
) -> BreakGlassGrant | None:
    now = now or datetime.now(UTC)
    grants = session.execute(
        select(BreakGlassGrant).where(
            BreakGlassGrant.organization_id == org_id,
            BreakGlassGrant.agent_id == agent_id,
        )
    ).scalars()
    for g in grants:
        expires = g.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires > now:
            return g
    return None


def is_agent_halted(
    session: Session,
    org: Organization,
    *,
    agent_id: str | None,
    now: datetime | None = None,
) -> bool:
    """True if the kill-switch is engaged and this agent has no active
    break-glass exception."""
    if not org.halt_all:
        return False
    if agent_id is None:
        return True
    return active_break_glass(session, org.id, agent_id=agent_id, now=now) is None


__all__ = [
    "active_break_glass",
    "engage",
    "grant_break_glass",
    "is_agent_halted",
    "release",
]
