from __future__ import annotations

import pytest

from app.services.egress import (
    EgressBlocked,
    assert_safe_webhook_url,
    is_safe_webhook_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://localhost:6379/",  # loopback
        "http://127.0.0.1/",
        "http://10.0.0.5:8080/",  # RFC1918
        "http://192.168.1.1/",
        "http://[::1]/",  # IPv6 loopback
        "ftp://example.com/x",  # disallowed scheme
        "file:///etc/passwd",
        "https:///no-host",
    ],
)
def test_blocks_internal_and_bad_schemes(url: str) -> None:
    assert is_safe_webhook_url(url) is False
    with pytest.raises(EgressBlocked):
        assert_safe_webhook_url(url)


def test_allows_public_https() -> None:
    # example.com resolves to public addresses.
    assert is_safe_webhook_url("https://example.com/hook") is True
