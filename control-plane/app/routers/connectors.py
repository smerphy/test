"""Notification connector CRUD + test delivery (admin)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import Finding, FindingSeverity, NotificationConnector, Organization, Role
from app.schemas import ConnectorIn, ConnectorOut, ConnectorUpdateIn
from app.services.crypto import seal
from app.services.notify_connectors import deliver_one

router = APIRouter(tags=["connectors"])


def _out(c: NotificationConnector) -> ConnectorOut:
    return ConnectorOut(
        id=c.id,
        name=c.name,
        type=c.type,
        config=c.config,
        min_severity=c.min_severity,
        enabled=c.enabled,
        secret_set=bool(c.secret),
        last_status=c.last_status,
        last_error=c.last_error,
        created_at=c.created_at,
    )


@router.post(
    "/notifications/connectors",
    response_model=ConnectorOut,
    status_code=status.HTTP_201_CREATED,
)
def create_connector(
    body: ConnectorIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> ConnectorOut:
    connector = NotificationConnector(
        organization_id=org.id,
        name=body.name,
        type=body.type.value,
        config=body.config,
        secret=seal(body.secret),
        min_severity=body.min_severity.value,
        enabled=body.enabled,
    )
    session.add(connector)
    try:
        with session.begin_nested():
            session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"a connector named {body.name!r} already exists",
        ) from exc
    return _out(connector)


@router.get("/notifications/connectors", response_model=list[ConnectorOut])
def list_connectors(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> list[ConnectorOut]:
    rows = session.execute(
        select(NotificationConnector)
        .where(NotificationConnector.organization_id == org.id)
        .order_by(NotificationConnector.created_at.desc())
    ).scalars()
    return [_out(c) for c in rows]


@router.patch(
    "/notifications/connectors/{connector_id}", response_model=ConnectorOut
)
def update_connector(
    connector_id: str,
    body: ConnectorUpdateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> ConnectorOut:
    connector = get_owned(
        session, NotificationConnector, connector_id, org,
        detail="connector not found",
    )
    fields = body.model_dump(exclude_unset=True)
    if fields.get("name"):
        connector.name = fields["name"]
    if "config" in fields and fields["config"] is not None:
        connector.config = fields["config"]
    if "secret" in fields:
        connector.secret = seal(fields["secret"])
    if "min_severity" in fields and fields["min_severity"] is not None:
        connector.min_severity = fields["min_severity"]
    if "enabled" in fields and fields["enabled"] is not None:
        connector.enabled = fields["enabled"]
    session.flush()
    return _out(connector)


@router.delete(
    "/notifications/connectors/{connector_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_connector(
    connector_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> None:
    connector = get_owned(
        session, NotificationConnector, connector_id, org,
        detail="connector not found",
    )
    session.delete(connector)
    session.flush()


@router.post("/notifications/connectors/{connector_id}/test")
def test_connector(
    connector_id: str,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> dict[str, int]:
    """Send a synthetic finding to one connector to validate its config."""
    connector = get_owned(
        session, NotificationConnector, connector_id, org,
        detail="connector not found",
    )
    now = datetime.now(UTC)
    sample = Finding(
        organization_id=org.id,
        rule_id="connector-test",
        title="Ephorate connector test",
        severity=FindingSeverity.CRITICAL,
        category="anomaly",
        dedup_key="connector-test",
        count=1,
        first_seen=now,
        last_seen=now,
        evidence={},
    )
    delivered = deliver_one(connector, sample, org)
    session.flush()
    return {"delivered": 1 if delivered else 0}
