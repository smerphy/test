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
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import session_user
from app.db import get_session
from app.models import Organization, Role, User
from app.services import mfa
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
    request.session["epoch"] = user.session_epoch
    # Escape the provider-supplied email before reflecting it into HTML.
    return HTMLResponse(
        f'<p>Signed in as {html.escape(email)}. <a href="/">Continue</a>.</p>'
    )


@router.post("/logout")
def logout(request: Request) -> dict[str, str]:
    request.session.clear()
    return {"status": "logged_out"}


@router.post("/logout-all")
def logout_all(
    request: Request,
    session: Session = Depends(get_session),
    user: User | None = Depends(session_user),
) -> dict[str, str]:
    """Revoke every session for the signed-in user (bump their epoch), then
    clear this one. Cookies issued before now stop working."""
    if user is not None:
        user.session_epoch += 1
        session.flush()
    request.session.clear()
    return {"status": "all_sessions_revoked"}


# --- MFA (TOTP) -------------------------------------------------------------
class MfaCodeIn(BaseModel):
    code: str


def _require_session_user(user: User | None) -> User:
    if user is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="sign in first"
        )
    return user


@router.post("/mfa/enroll")
def mfa_enroll(
    session: Session = Depends(get_session),
    user: User | None = Depends(session_user),
) -> dict[str, str]:
    """Begin TOTP enrollment: returns the secret + otpauth URI. MFA is not
    active until /auth/mfa/verify succeeds with a code."""
    u = _require_session_user(user)
    secret, uri = mfa.begin_enroll(u)
    session.flush()
    return {"secret": secret, "otpauth_uri": uri}


@router.post("/mfa/verify")
def mfa_verify(
    body: MfaCodeIn,
    request: Request,
    session: Session = Depends(get_session),
    user: User | None = Depends(session_user),
) -> dict[str, bool]:
    """Confirm enrollment (or complete step-up at login) with a TOTP code."""
    u = _require_session_user(user)
    ok = mfa.confirm(u, body.code) if not u.mfa_enabled else mfa.check(u, body.code)
    if ok:
        request.session["mfa_ok"] = True
        session.flush()
    return {"verified": ok}


@router.post("/mfa/disable")
def mfa_disable(
    body: MfaCodeIn,
    session: Session = Depends(get_session),
    user: User | None = Depends(session_user),
) -> dict[str, bool]:
    u = _require_session_user(user)
    disabled = mfa.disable(u, body.code)
    session.flush()
    return {"disabled": disabled}


# --- generic OIDC SSO -------------------------------------------------------
def _oidc_configured(settings: Settings) -> bool:
    return bool(
        settings.oidc_issuer
        and settings.oidc_client_id
        and settings.oidc_client_secret
    )


def _ensure_oidc_registered(settings: Settings) -> None:
    if "oidc" in _oauth._clients or not _oidc_configured(settings):
        return
    _oauth.register(
        name="oidc",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=(
            settings.oidc_issuer.rstrip("/")
            + "/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid email profile"},
    )


@router.get("/oidc/login")
async def oidc_login(
    request: Request, settings: Settings = Depends(get_settings)
) -> RedirectResponse:
    if not _oidc_configured(settings):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="OIDC not configured"
        )
    _ensure_oidc_registered(settings)
    redirect_uri = f"{settings.oauth_redirect_base_url}/auth/oidc/callback"
    redirect: RedirectResponse = await _oauth.oidc.authorize_redirect(
        request, redirect_uri
    )
    return redirect


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> HTMLResponse:
    if not _oidc_configured(settings):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="OIDC not configured"
        )
    _ensure_oidc_registered(settings)
    try:
        token = await _oauth.oidc.authorize_access_token(request)
    except OAuthError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail=f"oidc failed: {exc}"
        ) from exc
    userinfo = token.get("userinfo") or {}
    email = userinfo.get("email")
    if not email:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="no email in OIDC claims"
        )
    user = _upsert_user(session, email=email, name=userinfo.get("name"))
    request.session["user_id"] = user.id
    request.session["epoch"] = user.session_epoch
    # Fresh login: MFA step-up (if enabled) is required before data access.
    request.session.pop("mfa_ok", None)
    return HTMLResponse(
        f'<p>Signed in as {html.escape(email)}. <a href="/">Continue</a>.</p>'
    )


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

    # The first user to land in an org owns it; later teammates who auto-join
    # a shared corporate tenant default to the column's `admin` role and can
    # be adjusted by an owner via the /users API.
    has_members = session.execute(
        select(User.id).where(User.organization_id == org.id).limit(1)
    ).first()
    role = Role.ADMIN.value if has_members else Role.OWNER.value

    user = User(email=email, name=name, organization_id=org.id, role=role)
    session.add(user)
    session.flush()
    return user
