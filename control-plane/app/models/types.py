"""Custom SQLAlchemy column types.

``EncryptedJSON`` is a JSON column whose value is transparently sealed
(Fernet envelope-encrypted, see :mod:`app.services.crypto`) at rest when
field-level telemetry encryption is enabled, and unsealed on read. It is the
mechanism behind "sensitive telemetry payloads are encrypted at rest": the
richest PII sink in an audit event — the raw ``tool_arguments`` (and
``context`` / ``suggested_transform``) — is stored as ciphertext so a database
dump leaks nothing readable, while every Python read/write path keeps working
with plain dicts.

The transform is invisible to the tamper-evident hash chain: an event's hash is
computed by the SDK and verified against the plaintext ``AuditEventIn`` at
ingest (never recomputed from the stored row), and anchoring compares stored
hash strings — so what the payload columns hold at rest is orthogonal to
verification.

Encryption is opt-in (``EPHORATE_TELEMETRY_FIELD_ENCRYPTION`` + configured
``EPHORATE_SECRET_KEYS``) and backward-compatible: with the flag off (or no
keys) values are stored as ordinary JSON, and on read a plain JSON value is
returned untouched while a sealed string envelope is decrypted. Enabling or
disabling the flag over time therefore leaves older rows readable.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import JSON
from sqlalchemy.types import TypeDecorator

from app.services.crypto import seal, secrets_configured, unseal
from app.settings import get_settings


def _encryption_active() -> bool:
    return get_settings().telemetry_field_encryption and secrets_configured()


class EncryptedJSON(TypeDecorator[Any]):
    """A JSON column that seals its value at rest when telemetry field
    encryption is enabled. Stores a sealed string envelope (``enc:v1:…``) when
    active, or an ordinary JSON value otherwise."""

    impl = JSON
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if _encryption_active():
            # Seal the canonical JSON serialization into a string envelope.
            return seal(json.dumps(value, ensure_ascii=False, sort_keys=True))
        return value

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        # A sealed value round-trips through the JSON column as a string;
        # an unencrypted (or legacy) value comes back as its native dict/list.
        if isinstance(value, str):
            return json.loads(unseal(value) or "null")
        return value


__all__ = ["EncryptedJSON"]
