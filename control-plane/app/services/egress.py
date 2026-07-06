"""Egress guard for tenant-configured outbound webhook URLs.

Alert `target`s and the org `approval_webhook_url` are POSTed to by the
control plane from inside the trust boundary. Without validation an org admin
could point them at internal addresses (cloud metadata `169.254.169.254`,
`localhost`, RFC1918 hosts) and turn the control plane into an SSRF proxy.

`assert_safe_webhook_url` requires http(s) and rejects any URL whose host
resolves to a non-globally-routable address. It is called both at write time
(reject with 422) and immediately before each send (defeat a target that only
became internal after it was saved). A residual DNS-rebinding TOCTOU remains
between this resolution and httpx's own — pin egress via a proxy for full
coverage.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}


class EgressBlocked(ValueError):
    """Raised when an outbound URL is not permitted."""


def _address_is_disallowed(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    # Allowlist posture: only globally-routable addresses may be reached.
    return not ip.is_global


def assert_safe_webhook_url(url: str) -> None:
    """Raise `EgressBlocked` unless `url` is an http(s) URL whose host resolves
    exclusively to globally-routable addresses."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise EgressBlocked(f"scheme {parsed.scheme!r} not allowed; use http(s)")
    host = parsed.hostname
    if not host:
        raise EgressBlocked("URL has no host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(
            host, port, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as exc:
        raise EgressBlocked(f"could not resolve host {host!r}") from exc
    for info in infos:
        addr = str(info[4][0])
        if _address_is_disallowed(addr):
            raise EgressBlocked(
                f"host {host!r} resolves to a disallowed address ({addr})"
            )


def is_safe_webhook_url(url: str) -> bool:
    try:
        assert_safe_webhook_url(url)
        return True
    except EgressBlocked:
        return False


__all__ = ["EgressBlocked", "assert_safe_webhook_url", "is_safe_webhook_url"]
