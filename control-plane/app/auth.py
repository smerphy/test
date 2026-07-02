"""MVP auth: API-key header → Organization.

Production swap: OAuth/OIDC via Clerk or Auth.js; the dependency
contract stays `current_org`, so router code does not change.

For MVP, a single API key maps to a single Organization. Multi-tenancy
on a per-key basis comes next; for now we look up the org by slug
passed as a separate header, defaulting to the first key's owner.
"""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Organization, User
from app.settings import Settings, get_settings


def _check_api_key(api_key: str | None, settings: Settings) -> None:
    if not settings.api_keys:
        # Dev mode with no keys configured: allow everything. Loud-fail
        # in production is the caller's job (set PRAETOR_API_KEYS).
        return
    if api_key is None or api_key not in settings.api_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-API-Key",
        )


def current_user(
    request: Request,
    session: Session = Depends(get_session),
) -> User | None:
    """Return the signed-in User from the session, if any."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return session.get(User, user_id)


def current_org(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_org_slug: str | None = Header(default=None, alias="X-Org-Slug"),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Organization:
    """Resolve the calling Organization.

    Two credential paths:
      - browser: signed-in session cookie → user.organization
      - SDK / CLI: X-API-Key header, optionally X-Org-Slug
    """
    # 1) Session cookie path (humans).
    user = current_user(request, session)
    if user is not None:
        org = session.get(Organization, user.organization_id)
        if org is not None:
            return org

    # 2) API-key path (SDKs / CLI).
    _check_api_key(x_api_key, settings)

    # Resolve the organization this key is allowed to act as. A key must
    # not be able to reach an arbitrary tenant just by naming its slug in
    # X-Org-Slug — that is a cross-tenant breach.
    target_slug: str | None
    if not settings.api_keys:
        # Dev mode: no keys configured, auth is effectively open (see
        # _check_api_key). Resolve by the requested slug as before.
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
                        "configure PRAETOR_API_KEY_ORGS"
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
    return org


__all__ = ["current_org", "current_user"]
