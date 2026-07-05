"""Fleet & sensor management: heartbeat enrollment + fleet health."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import Agent, Organization, Role
from app.schemas import AgentOut, HeartbeatIn
from app.services.fleet import health_of, heartbeat, list_agents

router = APIRouter(tags=["fleet"])


def _to_out(agent: Agent) -> AgentOut:
    return AgentOut(
        id=agent.id,
        agent_id=agent.agent_id,
        name=agent.name,
        agent_version=agent.agent_version,
        sdk_version=agent.sdk_version,
        first_seen=agent.first_seen,
        last_seen=agent.last_seen,
        health=health_of(agent),
    )


@router.post(
    "/agents/heartbeat",
    response_model=AgentOut,
    status_code=status.HTTP_200_OK,
)
def post_heartbeat(
    body: HeartbeatIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> AgentOut:
    """Enroll a sensor (first contact) or refresh its last-seen."""
    agent = heartbeat(
        session,
        org_id=org.id,
        agent_id=body.agent_id,
        name=body.name,
        agent_version=body.agent_version,
        sdk_version=body.sdk_version,
    )
    session.flush()
    return _to_out(agent)


@router.get("/agents", response_model=list[AgentOut])
def list_fleet(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> list[AgentOut]:
    return [_to_out(a) for a in list_agents(session, org.id)]


@router.get("/agents/{agent_row_id}", response_model=AgentOut)
def get_agent(
    agent_row_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
) -> AgentOut:
    agent = get_owned(session, Agent, agent_row_id, org, detail="agent not found")
    return _to_out(agent)
