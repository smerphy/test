"""Direct tests for the cross-SDK audit-hash contract.

This module is the canonicalization + hashing contract shared by the Python
and TypeScript SDKs; a change here silently breaks chain interop, so it is
worth pinning directly.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta, timezone

import pytest

from ephorate_engine.audit_hash import (
    GENESIS_HASH,
    canonical_bytes,
    canonical_timestamp,
    compute_hash,
)


def test_genesis_hash_is_64_zeros() -> None:
    assert GENESIS_HASH == "0" * 64


def test_canonical_bytes_sorts_keys_and_strips_whitespace() -> None:
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_bytes_is_key_order_independent() -> None:
    assert canonical_bytes({"x": 1, "y": 2}) == canonical_bytes({"y": 2, "x": 1})


def test_canonical_bytes_utf8_not_ascii_escaped() -> None:
    assert canonical_bytes({"k": "café"}) == '{"k":"café"}'.encode()


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_canonical_bytes_rejects_non_finite_floats(bad: float) -> None:
    # Non-finite floats must not enter the chain: json would emit NaN/Infinity
    # tokens no other verifier can reproduce.
    with pytest.raises(ValueError):
        canonical_bytes({"cost": bad})


def test_compute_hash_is_stable_and_sha256_shaped() -> None:
    h = compute_hash({"a": 1, "b": [1, 2, 3]})
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
    assert compute_hash({"b": [1, 2, 3], "a": 1}) == h  # order-independent


def test_canonical_timestamp_utc_millis() -> None:
    ts = datetime(2026, 7, 10, 8, 30, 15, 123456, tzinfo=UTC)
    assert canonical_timestamp(ts) == "2026-07-10T08:30:15.123Z"


def test_canonical_timestamp_normalizes_offset_to_utc() -> None:
    # 12:00 at -05:00 is 17:00Z.
    ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone(timedelta(hours=-5)))
    assert canonical_timestamp(ts).startswith("2026-01-01T17:00:00")


def test_canonical_timestamp_rejects_naive() -> None:
    with pytest.raises(ValueError):
        canonical_timestamp(datetime(2026, 1, 1, 12, 0, 0))


def test_millisecond_truncation_not_rounding() -> None:
    ts = datetime(2026, 1, 1, 0, 0, 0, 999999, tzinfo=UTC)
    assert canonical_timestamp(ts) == "2026-01-01T00:00:00.999Z"
    assert math.isclose(999999 / 1000, 999.999)  # truncates to 999, not 1000
