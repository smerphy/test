"""MVP auth: API-key header → Organization.

Production swap: OAuth/OIDC via Clerk or Auth.js; the dependency
contract stays `current_org`, so router code does not change.

For MVP, a single API key maps to a single Organization. Multi-tenancy
on a per-key basis comes next; for now we look up the org by slug
passed as a separate header, defaulting to the first key's owner.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Organization, Role, User
from app.rbac import role_at_least
from app.settings import Settings, get_settings


def _check_api_key(api_key: str | None, settings: Settings) -> None:
    if not settings.api_keys:
        # No keys configured. Only allow-all in explicit dev mode; otherwise
        # fail closed so a deploy that forgets EPHORATE_API_KEYS is not silently
        # open to anonymous, any-tenant access.
        if settings.dev_mode:
            return
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API authentication is not configured",
        )
    if api_key is None or api_key not in settings.api_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-API-Key",
        )


def _resolve_session_user(
    request: Request, session: Session, *, enforce_mfa: bool
) -> User | None:
    """Resolve the signed-in User, applying lifecycle + session guards.

    A deprovisioned (``active=False``) user is denied; a session whose stamped
    epoch != the user's ``session_epoch`` is revoked (SCIM deprovision / "log
    out everywhere"); and when ``enforce_mfa`` an MFA-enabled user must have
    completed the step-up (``mfa_ok``) in this session.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    user = session.get(User, user_id)
    if user is None or not user.active:
        return None
    if request.session.get("epoch", 0) != user.session_epoch:
        return None
    if enforce_mfa and user.mfa_enabled and not request.session.get("mfa_ok"):
        return None
    return user


def current_user(
    request: Request,
    session: Session = Depends(get_session),
) -> User | None:
    """The signed-in User for data access — enforces the MFA step-up."""
    return _resolve_session_user(request, session, enforce_mfa=True)


def session_user(
    request: Request,
    session: Session = Depends(get_session),
) -> User | None:
    """The signed-in User for identity/self-service (MFA setup, logout-all)
    — skips the MFA step-up gate so a user can always complete verification."""
    return _resolve_session_user(request, session, enforce_mfa=False)


@dataclass(frozen=True)
class Principal:
    """The authenticated caller: their org and their RBAC role.

    ``kind`` distinguishes a human session (``"user"``) from a machine
    credential (``"api_key"``); ``user_id`` is set only for the former.
    """

    org: Organization
    role: Role
    kind: str
    user_id: str | None = None


def _api_key_role(api_key: str | None, settings: Settings) -> Role:
    """RBAC role for a valid API key.

    Dev mode with no configured keys grants OWNER for frictionless local
    work. Otherwise the key's role comes from ``api_key_roles`` (falling back
    to ``api_key_default_role``). An unrecognized configured value fails
    closed to VIEWER rather than silently escalating.
    """
    if not settings.api_keys:
        # Only reachable in dev mode (else _check_api_key already 401'd).
        return Role.OWNER
    raw = settings.api_key_roles.get(api_key or "", settings.api_key_default_role)
    try:
        return Role(raw)
    except ValueError:
        return Role.VIEWER


def current_principal(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_org_slug: str | None = Header(default=None, alias="X-Org-Slug"),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Principal:
    """Resolve the calling principal (org + role).

    Two credential paths:
      - browser: signed-in session cookie → user.organization + user.role
      - SDK / CLI: X-API-Key header, optionally X-Org-Slug → api_key role
    """
    # 1) Session cookie path (humans).
    user = current_user(request, session)
    if user is not None:
        org = session.get(Organization, user.organization_id)
        if org is not None:
            try:
                role = Role(user.role)
            except ValueError:
                role = Role.VIEWER
            return Principal(
                org=org, role=role, kind="user", user_id=user.id
            )

    # 2) API-key path (SDKs / CLI).
    _check_api_key(x_api_key, settings)

    # Resolve the organization this key is allowed to act as. A key must
    # not be able to reach an arbitrary tenant just by naming its slug in
    # X-Org-Slug — that is a cross-tenant breach.
    target_slug: str | None
    if not settings.api_keys:
        # Only reachable in dev mode (otherwise _check_api_key already 401'd).
        # Resolve by the requested slug for local development.
        target_slug = x_org_slug
    else:
        bound_slug = settings.api_key_orgs.get(x_api_key or "")
        if bound_slug is not None:
            # Key is scoped to one org. A mismatched X-Org-Slug is an attempt
            # to reach another tenant: reject it.
            if x_org_slug is not None and x_org_slug != bound_slug:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "API key is not authorized for the requested organization"
                    ),
                )
            target_slug = bound_slug
        else:
            # Valid but unbound key. Only safe when the deployment has a
            # single org; with multiple orgs an unscoped key must not be able
            # to pick one by slug.
            first_two = (
                session.execute(select(Organization).limit(2)).scalars().all()
            )
            if len(first_two) > 1:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "API key is not scoped to an organization; "
                        "configure EPHORATE_API_KEY_ORGS"
                    ),
                )
            target_slug = x_org_slug

    stmt = select(Organization)
    if target_slug:
        stmt = stmt.where(Organization.slug == target_slug)
    org = session.execute(stmt.limit(1)).scalar_one_or_none()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no organization found; create one via the bootstrap script",
        )
    return Principal(
        org=org, role=_api_key_role(x_api_key, settings), kind="api_key"
    )


def current_org(
    principal: Principal = Depends(current_principal),
) -> Organization:
    """The calling Organization.

    Thin wrapper over :func:`current_principal` so existing routers keep
    depending on ``current_org`` unchanged; FastAPI resolves the shared
    ``current_principal`` dependency once per request.
    """
    return principal.org


def require_role(
    minimum: Role,
) -> Callable[[Principal], Principal]:
    """Dependency factory: 403 unless the caller's role is >= ``minimum``.

    Use alongside ``current_org`` on mutating endpoints, e.g.::

        _p: Principal = Depends(require_role(Role.ADMIN))
    """

    def dependency(
        principal: Principal = Depends(current_principal),
    ) -> Principal:
        if not role_at_least(principal.role, minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"this action requires the '{minimum.value}' role or higher; "
                    f"the credential has '{principal.role.value}'"
                ),
            )
        return principal

    dependency.__name__ = f"require_role_{minimum.value}"
    return dependency


__all__ = [
    "Principal",
    "current_org",
    "current_principal",
    "current_user",
    "require_role",
    "session_user",
]
