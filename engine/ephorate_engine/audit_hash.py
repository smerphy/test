"""Canonical serialization + hashing for the tamper-evident audit chain.

Single source of truth shared by the Python SDK (writer), the control
plane (ingest verifier), and mirrored byte-for-byte by the TypeScript SDK.
The whole point of the audit chain is that anyone can recompute the hash;
that only holds if every party canonicalizes identically, so this lives in
one place rather than being re-implemented per component.

Contract:
  - timestamps: `YYYY-MM-DDTHH:MM:SS.sssZ` (millisecond precision, UTC, Z
    suffix) — matches JavaScript's `Date.prototype.toISOString()`.
  - JSON: sorted keys, no whitespace, and `ensure_ascii=False` so bytes
    are raw UTF-8 (matching JS `JSON.stringify`); a non-ASCII string must
    hash the same in every SDK.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Final

GENESIS_HASH: Final[str] = "0" * 64
"""SHA-256 placeholder used as the prev_hash of the first event in a chain."""


def canonical_timestamp(value: datetime) -> str:
    """Canonical wire format: `YYYY-MM-DDTHH:MM:SS.sssZ`.

    Raises `ValueError` on a naive datetime — an ambiguous instant must not
    silently enter a tamper-evident chain.
    """
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    aware = value.astimezone(UTC)
    ms = aware.microsecond // 1000
    return f"{aware.strftime('%Y-%m-%dT%H:%M:%S')}.{ms:03d}Z"


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, raw UTF-8."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_hash(payload: dict[str, Any]) -> str:
    """SHA-256 hex digest of the canonical bytes of `payload`."""
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


__all__ = [
    "GENESIS_HASH",
    "canonical_bytes",
    "canonical_timestamp",
    "compute_hash",
]
