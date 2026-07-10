"""RFC 6238 TOTP (time-based one-time passwords) — stdlib only, no new deps."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

_PERIOD = 30
_DIGITS = 6


def generate_secret() -> str:
    """A fresh base32 TOTP secret (160-bit)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    padding = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + padding)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % (10 ** _DIGITS):0{_DIGITS}d}"


def verify(secret_b32: str, code: str, *, at: float | None = None, window: int = 1) -> bool:
    """True if `code` is valid for `secret` within +/- `window` steps."""
    if not code or not code.strip().isdigit():
        return False
    code = code.strip()
    counter = int((at if at is not None else time.time()) // _PERIOD)
    return any(
        hmac.compare_digest(_hotp(secret_b32, counter + drift), code)
        for drift in range(-window, window + 1)
    )


def now_code(secret_b32: str, *, at: float | None = None) -> str:
    """The current code (used in tests / for QR-less enrollment help)."""
    counter = int((at if at is not None else time.time()) // _PERIOD)
    return _hotp(secret_b32, counter)


def provisioning_uri(secret_b32: str, email: str, issuer: str = "Ephorate") -> str:
    label = f"{quote(issuer)}:{quote(email)}"
    return (
        f"otpauth://totp/{label}?secret={secret_b32}"
        f"&issuer={quote(issuer)}&digits={_DIGITS}&period={_PERIOD}"
    )


__all__ = ["generate_secret", "now_code", "provisioning_uri", "verify"]
