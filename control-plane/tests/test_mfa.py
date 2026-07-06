"""TOTP MFA (primitive + lifecycle) and OIDC config gating."""

from __future__ import annotations

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Organization, User
from app.services import mfa, totp
from app.services.crypto import reset_cipher, unseal
from app.settings import get_settings


# --- TOTP primitive ---------------------------------------------------------
def test_totp_generate_and_verify() -> None:
    secret = totp.generate_secret()
    at = 1_800_000_000.0
    code = totp.now_code(secret, at=at)
    assert totp.verify(secret, code, at=at) is True
    assert totp.verify(secret, "000000", at=at) is False
    assert totp.verify(secret, "not-a-code", at=at) is False


def test_totp_window() -> None:
    secret = totp.generate_secret()
    at = 1_800_000_000.0
    prev = totp.now_code(secret, at=at - 30)
    # A code from the previous step verifies within the +/-1 window.
    assert totp.verify(secret, prev, at=at, window=1) is True
    assert totp.verify(secret, prev, at=at, window=0) is False


def test_provisioning_uri() -> None:
    uri = totp.provisioning_uri("ABC234", "a@acme.com", issuer="Praetor")
    assert uri.startswith("otpauth://totp/")
    assert "secret=ABC234" in uri


# --- MFA lifecycle over the User model --------------------------------------
def _user(session: Session, org: Organization) -> User:
    u = User(email="mfa@acme.com", organization_id=org.id, role="admin")
    session.add(u)
    session.commit()
    return u


def test_mfa_enroll_confirm_and_secret_encrypted(
    monkeypatch, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "secret_keys", [Fernet.generate_key().decode()])
    reset_cipher()
    u = _user(session, org)

    secret, _uri = mfa.begin_enroll(u)
    session.commit()
    assert u.mfa_enabled is False
    # Secret is encrypted at rest.
    assert u.mfa_secret is not None and u.mfa_secret.startswith("enc:v1:")
    assert unseal(u.mfa_secret) == secret

    # Wrong code fails; correct code activates MFA.
    assert mfa.confirm(u, "000000") is False
    assert u.mfa_enabled is False
    assert mfa.confirm(u, totp.now_code(secret)) is True
    assert u.mfa_enabled is True


def test_mfa_check_and_disable(session: Session, org: Organization) -> None:
    u = _user(session, org)
    secret, _ = mfa.begin_enroll(u)
    mfa.confirm(u, totp.now_code(secret))
    session.commit()

    assert mfa.check(u, totp.now_code(secret)) is True
    assert mfa.check(u, "000000") is False
    # Disable requires a valid code.
    assert mfa.disable(u, "000000") is False
    assert mfa.disable(u, totp.now_code(secret)) is True
    assert u.mfa_enabled is False
    assert u.mfa_secret is None


def test_mfa_endpoints_require_session(client: TestClient) -> None:
    # API-key path has no session user → 401.
    assert client.post("/auth/mfa/enroll").status_code == 401
    assert client.post("/auth/mfa/verify", json={"code": "123456"}).status_code == 401


# --- OIDC config gating -----------------------------------------------------
def test_oidc_login_503_when_unconfigured(client: TestClient) -> None:
    assert client.get("/auth/oidc/login", follow_redirects=False).status_code == 503
    assert client.get("/auth/oidc/callback").status_code == 503


def test_oidc_configured_flag(monkeypatch) -> None:
    from app.routers.auth import _oidc_configured

    s = get_settings()
    assert _oidc_configured(s) is False
    monkeypatch.setattr(s, "oidc_issuer", "https://idp.example.com")
    monkeypatch.setattr(s, "oidc_client_id", "cid")
    monkeypatch.setattr(s, "oidc_client_secret", "csecret")
    assert _oidc_configured(s) is True
