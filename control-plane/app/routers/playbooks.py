"""SOAR response playbook CRUD + execution history.

Playbooks are configuration (ADMIN). Execution history is SOC-facing (ANALYST):
it shows what automated response fired on which finding.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import Organization, PlaybookExecution, ResponsePlaybook, Role
from app.schemas import (
    PlaybookExecutionOut,
    PlaybookIn,
    PlaybookOut,
    PlaybookUpdateIn,
)

router = APIRouter(tags=["soar"])


@router.post(
    "/soar/playbooks",
    response_model=PlaybookOut,
    status_code=status.HTTP_201_CREATED,
)
def create_playbook(
    body: PlaybookIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> ResponsePlaybook:
    playbook = ResponsePlaybook(
        organization_id=org.id,
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        priority=body.priority,
        stop_on_match=body.stop_on_match,
        conditions=body.conditions.model_dump(exclude_none=True),
        actions=[a.model_dump() for a in body.actions],
    )
    session.add(playbook)
    try:
        with session.begin_nested():
            session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"a playbook named {body.name!r} already exists",
        ) from exc
    return playbook


@router.get("/soar/playbooks", response_model=list[PlaybookOut])
def list_playbooks(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> list[ResponsePlaybook]:
    return list(
        session.execute(
            select(ResponsePlaybook)
            .where(ResponsePlaybook.organization_id == org.id)
            .order_by(
                ResponsePlaybook.priority.asc(), ResponsePlaybook.created_at.asc()
            )
        ).scalars()
    )


@router.get("/soar/playbooks/{playbook_id}", response_model=PlaybookOut)
def get_playbook(
    playbook_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
) -> ResponsePlaybook:
    return get_owned(
        session, ResponsePlaybook, playbook_id, org, detail="playbook not found"
    )


@router.patch("/soar/playbooks/{playbook_id}", response_model=PlaybookOut)
def update_playbook(
    playbook_id: str,
    body: PlaybookUpdateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> ResponsePlaybook:
    playbook = get_owned(
        session, ResponsePlaybook, playbook_id, org, detail="playbook not found"
    )
    fields = body.model_dump(exclude_unset=True)
    if fields.get("name"):
        playbook.name = fields["name"]
    if "description" in fields:
        playbook.description = fields["description"]
    if "enabled" in fields and fields["enabled"] is not None:
        playbook.enabled = fields["enabled"]
    if "priority" in fields and fields["priority"] is not None:
        playbook.priority = fields["priority"]
    if "stop_on_match" in fields and fields["stop_on_match"] is not None:
        playbook.stop_on_match = fields["stop_on_match"]
    if body.conditions is not None:
        playbook.conditions = body.conditions.model_dump(exclude_none=True)
    if body.actions is not None:
        playbook.actions = [a.model_dump() for a in body.actions]
    try:
        with session.begin_nested():
            session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"a playbook named {fields.get('name')!r} already exists",
        ) from exc
    return playbook


@router.delete(
    "/soar/playbooks/{playbook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_playbook(
    playbook_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> None:
    playbook = get_owned(
        session, ResponsePlaybook, playbook_id, org, detail="playbook not found"
    )
    session.delete(playbook)
    session.flush()


@router.get("/soar/executions", response_model=list[PlaybookExecutionOut])
def list_executions(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ANALYST)),
    finding_id: Annotated[str | None, Query()] = None,
    playbook_id: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[PlaybookExecution]:
    stmt = select(PlaybookExecution).where(
        PlaybookExecution.organization_id == org.id
    )
    if finding_id is not None:
        stmt = stmt.where(PlaybookExecution.finding_id == finding_id)
    if playbook_id is not None:
        stmt = stmt.where(PlaybookExecution.playbook_id == playbook_id)
    stmt = stmt.order_by(PlaybookExecution.created_at.desc()).limit(limit)
    return list(session.execute(stmt).scalars())
