"""SCIM 2.0 user provisioning (RFC 7644, Users resource).

Lets an IdP (Okta, Azure AD, OneLogin, …) create, update, and — critically —
deprovision users automatically. Authenticated with a per-org bearer token
(`Authorization: Bearer <token>` mapped to an org via EPHORATE_SCIM_TOKENS).
Deprovisioning (active=false / DELETE) also revokes the user's live sessions.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Organization, Role, User
from app.settings import Settings, get_settings

router = APIRouter(tags=["scim"])

_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def scim_org(
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Organization:
    """Resolve the org from a SCIM bearer token."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="missing SCIM bearer token"
        )
    token = auth[7:].strip()
    slug = settings.scim_tokens.get(token)
    if slug is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="invalid SCIM token"
        )
    org = session.execute(
        select(Organization).where(Organization.slug == slug)
    ).scalar_one_or_none()
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="org not found")
    return org


def _repr(user: User) -> dict[str, Any]:
    return {
        "schemas": [_USER_SCHEMA],
        "id": user.id,
        "externalId": user.external_id,
        "userName": user.email,
        "name": {"formatted": user.name} if user.name else {},
        "displayName": user.name,
        "active": user.active,
        "meta": {"resourceType": "User", "location": f"/scim/v2/Users/{user.id}"},
    }


def _error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(
        status_code,
        detail={"schemas": [_ERROR_SCHEMA], "detail": detail, "status": str(status_code)},
    )


def _revoke(user: User) -> None:
    user.session_epoch += 1


@router.post("/scim/v2/Users", status_code=status.HTTP_201_CREATED)
def create_user(
    body: dict[str, Any],
    org: Organization = Depends(scim_org),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    email = (body.get("userName") or "").strip().lower()
    if not email:
        raise _error(status.HTTP_400_BAD_REQUEST, "userName is required")
    existing = session.execute(
        select(User).where(User.email == email)
    ).scalar_one_or_none()
    if existing is not None:
        raise _error(status.HTTP_409_CONFLICT, "user already exists")
    name = body.get("displayName") or (body.get("name") or {}).get("formatted")
    user = User(
        email=email,
        name=name,
        organization_id=org.id,
        role=Role.VIEWER.value,  # provisioned users start least-privileged
        active=bool(body.get("active", True)),
        external_id=body.get("externalId"),
    )
    session.add(user)
    session.flush()
    return _repr(user)


@router.get("/scim/v2/Users")
def list_users(
    org: Organization = Depends(scim_org),
    session: Session = Depends(get_session),
    filter: str | None = None,
    startIndex: int = 1,
    count: int = 100,
) -> dict[str, Any]:
    stmt = select(User).where(User.organization_id == org.id)
    # Support the one filter IdPs actually send: userName eq "x".
    if filter and "userName" in filter and " eq " in filter:
        value = filter.split(" eq ", 1)[1].strip().strip('"').lower()
        stmt = stmt.where(User.email == value)
    users = list(session.execute(stmt).scalars())
    page = users[max(0, startIndex - 1) : max(0, startIndex - 1) + count]
    return {
        "schemas": [_LIST_SCHEMA],
        "totalResults": len(users),
        "startIndex": startIndex,
        "itemsPerPage": len(page),
        "Resources": [_repr(u) for u in page],
    }


def _get_scoped(session: Session, org: Organization, user_id: str) -> User:
    user = session.get(User, user_id)
    if user is None or user.organization_id != org.id:
        raise _error(status.HTTP_404_NOT_FOUND, "user not found")
    return user


@router.get("/scim/v2/Users/{user_id}")
def get_user(
    user_id: str,
    org: Organization = Depends(scim_org),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    return _repr(_get_scoped(session, org, user_id))


@router.put("/scim/v2/Users/{user_id}")
def replace_user(
    user_id: str,
    body: dict[str, Any],
    org: Organization = Depends(scim_org),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    user = _get_scoped(session, org, user_id)
    if "displayName" in body or "name" in body:
        user.name = body.get("displayName") or (body.get("name") or {}).get(
            "formatted"
        )
    if "active" in body:
        new_active = bool(body["active"])
        if user.active and not new_active:
            _revoke(user)
        user.active = new_active
    session.flush()
    return _repr(user)


@router.patch("/scim/v2/Users/{user_id}")
def patch_user(
    user_id: str,
    body: dict[str, Any],
    org: Organization = Depends(scim_org),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    user = _get_scoped(session, org, user_id)
    # Apply the PatchOp operations we understand (active toggle, displayName).
    for op in body.get("Operations", []):
        if not isinstance(op, dict):
            continue
        path = str(op.get("path", "")).lower()
        value = op.get("value")
        if path == "active" or (path == "" and isinstance(value, dict) and "active" in value):
            active = value.get("active") if isinstance(value, dict) else value
            active = bool(active)
            if user.active and not active:
                _revoke(user)
            user.active = active
        elif path in ("displayname", "name.formatted"):
            user.name = value if isinstance(value, str) else user.name
    session.flush()
    return _repr(user)


@router.delete("/scim/v2/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: str,
    org: Organization = Depends(scim_org),
    session: Session = Depends(get_session),
) -> None:
    # SCIM DELETE = deprovision. Soft-deactivate + revoke sessions rather than
    # hard-delete so the audit trail and RBAC history survive.
    user = _get_scoped(session, org, user_id)
    if user.active:
        user.active = False
        _revoke(user)
    session.flush()
