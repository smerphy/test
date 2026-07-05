"""Organization membership + RBAC role management.

Owners manage who can do what. Listing members is admin-visible; changing a
role is owner-only, and the last owner cannot be demoted (which would leave
the org with no one able to manage roles).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import Principal, current_org, current_principal, require_role
from app.db import get_session
from app.deps import get_owned
from app.models import Organization, Role, User
from app.schemas import UserOut, UserUpdateIn

router = APIRouter(tags=["users"])


@router.get("/users", response_model=list[UserOut])
def list_users(
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.ADMIN)),
) -> list[User]:
    stmt = (
        select(User)
        .where(User.organization_id == org.id)
        .order_by(User.created_at.asc())
    )
    return list(session.execute(stmt).scalars().all())


@router.get("/users/me", response_model=UserOut)
def get_me(
    session: Session = Depends(get_session),
    principal: Principal = Depends(current_principal),
) -> User:
    """The signed-in user's own membership record.

    Only meaningful on the session-cookie path; API-key callers have no user
    record and get a 404.
    """
    if principal.kind != "user" or principal.user_id is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="no user is associated with this credential",
        )
    user = session.get(User, principal.user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    body: UserUpdateIn,
    org: Organization = Depends(current_org),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_role(Role.OWNER)),
) -> User:
    """Change a member's role or display name. Owner-only.

    Guards against removing the last owner so an org can never become
    unmanageable.
    """
    user = get_owned(
        session,
        User,
        user_id,
        org,
        owner=lambda u: u.organization_id,
        detail="user not found",
    )
    fields = body.model_dump(exclude_unset=True)
    if "name" in fields:
        user.name = fields["name"]
    if "role" in fields and fields["role"] is not None:
        new_role = Role(fields["role"])
        if user.role == Role.OWNER.value and new_role is not Role.OWNER:
            owner_count = session.execute(
                select(func.count())
                .select_from(User)
                .where(
                    User.organization_id == org.id,
                    User.role == Role.OWNER.value,
                )
            ).scalar_one()
            if owner_count <= 1:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail=(
                        "cannot demote the last owner; promote another member "
                        "to owner first"
                    ),
                )
        user.role = new_role.value
    session.flush()
    return user
