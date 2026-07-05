"""Fleet/sensor management: heartbeat enrollment + health."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Agent

# An agent is "stale" if it hasn't reported in within this window.
STALE_AFTER_MINUTES = 15


def heartbeat(
    session: Session,
    *,
    org_id: str,
    agent_id: str,
    name: str | None = None,
    agent_version: str | None = None,
    sdk_version: str | None = None,
    now: datetime | None = None,
) -> Agent:
    """Enroll on first contact / refresh last_seen on every heartbeat."""
    now = now or datetime.now(UTC)
    existing = session.execute(
        select(Agent).where(
            Agent.organization_id == org_id, Agent.agent_id == agent_id
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.last_seen = now
        if name is not None:
            existing.name = name
        if agent_version is not None:
            existing.agent_version = agent_version
        if sdk_version is not None:
            existing.sdk_version = sdk_version
        return existing
    agent = Agent(
        organization_id=org_id,
        agent_id=agent_id,
        name=name,
        agent_version=agent_version,
        sdk_version=sdk_version,
        first_seen=now,
        last_seen=now,
    )
    session.add(agent)
    try:
        with session.begin_nested():
            session.flush()
    except IntegrityError:
        # A concurrent heartbeat enrolled the same agent first; fetch it.
        agent = session.execute(
            select(Agent).where(
                Agent.organization_id == org_id, Agent.agent_id == agent_id
            )
        ).scalar_one()
        agent.last_seen = now
    return agent


def health_of(agent: Agent, *, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    last = agent.last_seen
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    if now - last <= timedelta(minutes=STALE_AFTER_MINUTES):
        return "active"
    return "stale"


def list_agents(session: Session, org_id: str, *, limit: int = 500) -> list[Agent]:
    return list(
        session.execute(
            select(Agent)
            .where(Agent.organization_id == org_id)
            .order_by(Agent.last_seen.desc())
            .limit(limit)
        ).scalars()
    )


__all__ = ["STALE_AFTER_MINUTES", "health_of", "heartbeat", "list_agents"]
