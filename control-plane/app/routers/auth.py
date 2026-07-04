"""OAuth (GitHub) for human sign-in via the web UI.

On callback we ensure a `User` exists (linked to the Organization for
their email domain, creating it if none exists) and store the user id
in the session cookie. The session
cookie is the auth credential for browser-driven traffic; API keys
remain the credential for SDK-driven traffic.
"""

from __future__ import annotations

import hashlib
import html

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Organization, User
from app.settings import Settings, get_settings

router = APIRouter(prefix="/auth", tags=["auth"])

# Free-mail domains that must never auto-join a shared tenant (they are not
# owned by a single organization). Users on these get an isolated per-user org.
_PUBLIC_EMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "ymail.com",
        "icloud.com",
        "me.com",
        "aol.com",
        "proton.me",
        "protonmail.com",
        "pm.me",
        "gmx.com",
        "mail.com",
        "yandex.com",
        "zoho.com",
        "fastmail.com",
        "hey.com",
    }
)

_oauth = OAuth()


def _ensure_provider_registered(settings: Settings) -> None:
    if "github" in _oauth._clients:
        return
    if not settings.github_client_id or not settings.github_client_secret:
        return
    _oauth.register(
        name="github",
        client_id=settings.github_client_id,
        client_secret=settings.github_client_secret,
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "read:user user:email"},
    )


def _provider_configured(settings: Settings) -> bool:
    return bool(settings.github_client_id and settings.github_client_secret)


@router.get("/login")
async def login(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    if not _provider_configured(settings):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth provider not configured",
        )
    _ensure_provider_registered(settings)
    redirect_uri = f"{settings.oauth_redirect_base_url}/auth/callback"
    redirect: RedirectResponse = await _oauth.github.authorize_redirect(
        request, redirect_uri
    )
    return redirect


@router.get("/callback")
async def callback(
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> HTMLResponse:
    if not _provider_configured(settings):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth provider not configured",
        )
    _ensure_provider_registered(settings)
    try:
        token = await _oauth.github.authorize_access_token(request)
    except OAuthError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail=f"oauth failed: {exc}"
        ) from exc

    resp = await _oauth.github.get("user", token=token)
    profile = resp.json()
    email = profile.get("email")
    if not email:
        emails_resp = await _oauth.github.get("user/emails", token=token)
        emails = emails_resp.json()
        primary = next(
            (e for e in emails if e.get("primary") and e.get("verified")), None
        )
        if primary is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail="no verified primary email on GitHub account",
            )
        email = primary["email"]

    user = _upsert_user(session, email=email, name=profile.get("name"))
    request.session["user_id"] = user.id
    # Escape the provider-supplied email before reflecting it into HTML.
    return HTMLResponse(
        f'<p>Signed in as {html.escape(email)}. <a href="/">Continue</a>.</p>'
    )


@router.post("/logout")
def logout(request: Request) -> dict[str, str]:
    request.session.clear()
    return {"status": "logged_out"}


def _upsert_user(session: Session, *, email: str, name: str | None) -> User:
    user = session.execute(
        select(User).where(User.email == email)
    ).scalar_one_or_none()
    if user is not None:
        return user

    # New user tenanting. For a corporate domain, verified teammates on the
    # same domain share a tenant. For a public free-mail domain, that would
    # dump every unrelated gmail.com/outlook.com signup into ONE shared org
    # (a cross-tenant data leak), so give each such user their own isolated
    # org keyed on their verified email instead. Never fall back to "the
    # first organization".
    domain = (email.rsplit("@", 1)[1] if "@" in email else "default").lower()
    if domain in _PUBLIC_EMAIL_DOMAINS:
        slug = "user-" + hashlib.sha256(email.encode()).hexdigest()[:16]
        org_name = email
    else:
        slug = domain.replace(".", "-")
        org_name = domain.capitalize()
    org = session.execute(
        select(Organization).where(Organization.slug == slug)
    ).scalar_one_or_none()
    if org is None:
        org = Organization(name=org_name, slug=slug)
        session.add(org)
        session.flush()

    user = User(email=email, name=name, organization_id=org.id)
    session.add(user)
    session.flush()
    return user
