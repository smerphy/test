"""Shared HTTP client lifecycle helper.

Several services accept an optional injected ``httpx.Client`` (so tests and
callers can supply a mock or a shared pool) and otherwise create one locally.
A locally-created client owns a connection pool that must be closed, or its
sockets/file descriptors leak until GC. ``owned_client`` yields a client and
closes it only when it was created here — never a caller-supplied one.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any

import httpx


@contextlib.contextmanager
def owned_client(
    injected: httpx.Client | None, **kwargs: Any
) -> Iterator[httpx.Client]:
    client = injected or httpx.Client(**kwargs)
    try:
        yield client
    finally:
        if injected is None:
            client.close()


__all__ = ["owned_client"]
