"""TOTP MFA lifecycle over the User model (secret encrypted at rest)."""

from __future__ import annotations

from app.models import User
from app.services import totp
from app.services.crypto import seal, unseal


def begin_enroll(user: User, *, issuer: str = "Praetor") -> tuple[str, str]:
    """Generate + store (pending) a TOTP secret. Returns (secret, otpauth_uri).
    MFA is not active until `confirm` succeeds."""
    secret = totp.generate_secret()
    user.mfa_secret = seal(secret)
    user.mfa_enabled = False
    return secret, totp.provisioning_uri(secret, user.email, issuer)


def confirm(user: User, code: str) -> bool:
    """Verify the first code and activate MFA."""
    secret = unseal(user.mfa_secret)
    if not secret or not totp.verify(secret, code):
        return False
    user.mfa_enabled = True
    return True


def check(user: User, code: str) -> bool:
    """Verify a code for an MFA-enabled user (step-up at login)."""
    if not user.mfa_enabled:
        return False
    secret = unseal(user.mfa_secret)
    return bool(secret and totp.verify(secret, code))


def disable(user: User, code: str) -> bool:
    """Turn MFA off (requires a valid current code)."""
    if not check(user, code):
        return False
    user.mfa_enabled = False
    user.mfa_secret = None
    return True


__all__ = ["begin_enroll", "check", "confirm", "disable"]
