"""Envelope encryption for secrets at rest (BYO API keys, feed auth headers).

Tenant secrets — ``organizations.ai_api_key`` and ``threat_feeds.auth_header``
— are Fernet-encrypted before they touch the database and decrypted only at
the moment of use. A DB dump therefore leaks ciphertext, not keys.

Key rotation is supported via ``MultiFernet``: set ``PRAETOR_SECRET_KEYS`` to a
comma-separated list; the FIRST key encrypts new values, and ALL keys are
tried on decrypt. To rotate, prepend a fresh key — old ciphertext still
decrypts and is re-sealed with the new key on its next write.

Sealed values carry an ``enc:v1:`` prefix so plaintext written before
encryption was enabled (or in dev with no keys) is transparently passed
through by :func:`unseal`.

Generate a key with::

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.settings import get_settings

_PREFIX = "enc:v1:"
_cipher: MultiFernet | None = None
_cipher_loaded = False


class SecretsError(RuntimeError):
    """Raised when a sealed value cannot be decrypted (misconfigured keys)."""


def _get_cipher() -> MultiFernet | None:
    global _cipher, _cipher_loaded
    if not _cipher_loaded:
        keys = get_settings().secret_keys
        if keys:
            try:
                _cipher = MultiFernet([Fernet(k.encode()) for k in keys])
            except (ValueError, TypeError) as exc:
                raise SecretsError(
                    "PRAETOR_SECRET_KEYS contains an invalid Fernet key"
                ) from exc
        else:
            _cipher = None
        _cipher_loaded = True
    return _cipher


def reset_cipher() -> None:
    """Drop the cached cipher (tests reconfigure keys between cases)."""
    global _cipher, _cipher_loaded
    _cipher = None
    _cipher_loaded = False


def secrets_configured() -> bool:
    return _get_cipher() is not None


def seal(plaintext: str | None) -> str | None:
    """Encrypt a secret for storage. Returns plaintext unchanged when no keys
    are configured (dev), so the column is still writable."""
    if plaintext is None or plaintext == "":
        return plaintext
    cipher = _get_cipher()
    if cipher is None:
        return plaintext
    return _PREFIX + cipher.encrypt(plaintext.encode()).decode()


def unseal(value: str | None) -> str | None:
    """Decrypt a stored secret. Values without the sealed prefix (legacy
    plaintext / dev) are returned as-is."""
    if value is None or not value.startswith(_PREFIX):
        return value
    cipher = _get_cipher()
    if cipher is None:
        raise SecretsError(
            "a sealed secret was found but PRAETOR_SECRET_KEYS is not configured"
        )
    try:
        return cipher.decrypt(value[len(_PREFIX) :].encode()).decode()
    except InvalidToken as exc:
        raise SecretsError(
            "could not decrypt a sealed secret (wrong or rotated-out key)"
        ) from exc


__all__ = [
    "SecretsError",
    "reset_cipher",
    "seal",
    "secrets_configured",
    "unseal",
]
