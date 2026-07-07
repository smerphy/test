from __future__ import annotations

from ephorate_engine.redaction import redact_text, redact_value


def test_redacts_common_pii() -> None:
    red, types = redact_text(
        "email alice@acme.com ssn 123-45-6789 key AKIAIOSFODNN7EXAMPLE "
        "phone 555-123-4567"
    )
    assert "alice@acme.com" not in red
    assert "123-45-6789" not in red
    assert "AKIAIOSFODNN7EXAMPLE" not in red
    assert {"email", "ssn", "aws_key", "phone"} <= types


def test_redacts_jwt_and_private_key() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc-DEF_123"
    red, types = redact_text(f"token {jwt}")
    assert jwt not in red
    assert "token" in types

    red2, types2 = redact_text("-----BEGIN RSA PRIVATE KEY-----\nMIIB...")
    assert "PRIVATE KEY" not in red2
    assert "private_key" in types2


def test_card_luhn_gating() -> None:
    red, types = redact_text("card 4111111111111111")
    assert "4111111111111111" not in red
    assert "card" in types
    # Non-Luhn 16-digit run is not treated as a card.
    _red, types2 = redact_text("id 1234567812345670000")
    assert "card" not in types2


def test_clean_text_unchanged() -> None:
    text = "agent invoked shell.exec to read /var/log/app.log"
    red, types = redact_text(text)
    assert red == text
    assert types == set()


def test_empty_text() -> None:
    assert redact_text("") == ("", set())


def test_redact_value_nested() -> None:
    obj = {
        "user": "bob@corp.com",
        "items": ["ok", "ssn 123-45-6789"],
        "count": 3,
        "nested": {"card": "4111111111111111"},
    }
    red, types = redact_value(obj)
    assert "bob@corp.com" not in str(red)
    assert "123-45-6789" not in str(red)
    assert "4111111111111111" not in str(red)
    assert red["count"] == 3  # non-strings untouched
    assert {"email", "ssn", "card"} <= types


def test_redact_value_scalars_passthrough() -> None:
    assert redact_value(42) == (42, set())
    assert redact_value(None) == (None, set())
    assert redact_value(True) == (True, set())
