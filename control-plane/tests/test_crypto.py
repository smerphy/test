"""Secrets at rest: envelope encryption, rotation, and end-to-end sealing."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Organization, ThreatFeed
from app.services.ai.config import org_llm_config
from app.services.crypto import (
    SecretsError,
    reset_cipher,
    seal,
    secrets_configured,
    unseal,
)
from app.settings import get_settings


def _set_keys(monkeypatch, keys: list[str]) -> None:
    monkeypatch.setattr(get_settings(), "secret_keys", keys)
    reset_cipher()


def test_seal_roundtrip(monkeypatch) -> None:
    _set_keys(monkeypatch, [Fernet.generate_key().decode()])
    sealed = seal("sk-super-secret")
    assert sealed is not None
    assert sealed.startswith("enc:v1:")
    assert "sk-super-secret" not in sealed
    assert unseal(sealed) == "sk-super-secret"


def test_no_keys_is_passthrough(monkeypatch) -> None:
    _set_keys(monkeypatch, [])
    assert secrets_configured() is False
    assert seal("plain") == "plain"  # dev: stored as-is
    assert unseal("plain") == "plain"


def test_unseal_legacy_plaintext(monkeypatch) -> None:
    # A value written before encryption was enabled has no prefix.
    _set_keys(monkeypatch, [Fernet.generate_key().decode()])
    assert unseal("legacy-plaintext") == "legacy-plaintext"


def test_key_rotation(monkeypatch) -> None:
    old = Fernet.generate_key().decode()
    new = Fernet.generate_key().decode()
    _set_keys(monkeypatch, [old])
    sealed_old = seal("secret")

    # Rotate: new key first, old key still present for decrypt.
    _set_keys(monkeypatch, [new, old])
    assert unseal(sealed_old) == "secret"  # old ciphertext still decrypts
    sealed_new = seal("secret")
    assert unseal(sealed_new) == "secret"

    # Retire the old key: old ciphertext no longer decrypts.
    _set_keys(monkeypatch, [new])
    assert unseal(sealed_new) == "secret"
    with pytest.raises(SecretsError):
        unseal(sealed_old)


def test_sealed_without_keys_raises(monkeypatch) -> None:
    _set_keys(monkeypatch, [Fernet.generate_key().decode()])
    sealed = seal("secret")
    _set_keys(monkeypatch, [])
    with pytest.raises(SecretsError):
        unseal(sealed)


def test_ai_key_encrypted_at_rest_end_to_end(
    monkeypatch, client: TestClient, session: Session, org: Organization
) -> None:
    _set_keys(monkeypatch, [Fernet.generate_key().decode()])
    r = client.patch(
        "/ai/config",
        json={
            "ai_enabled": True,
            "ai_provider": "anthropic",
            "ai_model": "claude-x",
            "ai_api_key": "sk-plaintext-secret",
        },
    )
    assert r.status_code == 200
    # Stored value is ciphertext, not the plaintext.
    session.expire_all()
    stored = session.get(Organization, org.id)
    assert stored is not None
    assert stored.ai_api_key is not None
    assert stored.ai_api_key.startswith("enc:v1:")
    assert "sk-plaintext-secret" not in stored.ai_api_key
    # But org_llm_config decrypts it for use.
    cfg = org_llm_config(stored, get_settings())
    assert cfg is not None
    assert cfg.api_key == "sk-plaintext-secret"


def test_feed_auth_header_encrypted(
    monkeypatch, client: TestClient, session: Session, org: Organization
) -> None:
    _set_keys(monkeypatch, [Fernet.generate_key().decode()])
    r = client.post(
        "/threat/feeds",
        json={
            "name": "auth-feed",
            "format": "plaintext",
            "default_indicator_type": "domain",
            "auth_header": "Authorization: Token abc123",
        },
    )
    assert r.status_code == 201
    feed = session.get(ThreatFeed, r.json()["id"])
    assert feed is not None
    assert feed.auth_header is not None
    assert feed.auth_header.startswith("enc:v1:")
    assert "abc123" not in feed.auth_header
    assert unseal(feed.auth_header) == "Authorization: Token abc123"
