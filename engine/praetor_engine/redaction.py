"""PII redaction shared by the SDK (pre-hash audit redaction) and the control
plane (finding-ingest redaction).

Detects and masks common sensitive tokens in free text — emails, US SSNs,
Luhn-valid payment cards, phone numbers, AWS access keys, JWT/bearer tokens,
and PEM private-key headers — replacing each with a ``[REDACTED:<type>]``
marker. `redact_value` walks JSON-like structures.

Keeping the single implementation in the engine (a dependency of both the SDK
and the control plane) means audit events can be redacted *before* the
tamper-evident hash is computed, without the two sides drifting.
"""

from __future__ import annotations

import re
from typing import Any

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")
_PHONE = re.compile(
    r"\b(?:\+?\d{1,2}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b"
)
# 13-19 digit runs (optionally separated) — Luhn-validated below to cut FPs.
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def redact_text(text: str) -> tuple[str, set[str]]:
    """Mask PII in a string. Returns (redacted, set of PII types found)."""
    if not text:
        return text, set()
    found: set[str] = set()

    def _sub(pattern: re.Pattern[str], label: str, s: str) -> str:
        def repl(_m: re.Match[str]) -> str:
            found.add(label)
            return f"[REDACTED:{label}]"

        return pattern.sub(repl, s)

    out = text
    out = _sub(_PRIVATE_KEY, "private_key", out)
    out = _sub(_JWT, "token", out)
    out = _sub(_AWS_KEY, "aws_key", out)
    out = _sub(_EMAIL, "email", out)
    out = _sub(_SSN, "ssn", out)

    def _card_repl(m: re.Match[str]) -> str:
        if _luhn_ok(m.group(0)):
            found.add("card")
            return "[REDACTED:card]"
        return m.group(0)

    out = _CARD.sub(_card_repl, out)
    out = _sub(_PHONE, "phone", out)
    return out, found


def redact_value(value: Any) -> tuple[Any, set[str]]:
    """Recursively redact PII in a JSON-like structure. Returns (value, types)."""
    found: set[str] = set()
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out_d: dict[Any, Any] = {}
        for k, v in value.items():
            rv, t = redact_value(v)
            out_d[k] = rv
            found |= t
        return out_d, found
    if isinstance(value, list):
        out_l: list[Any] = []
        for v in value:
            rv, t = redact_value(v)
            out_l.append(rv)
            found |= t
        return out_l, found
    return value, found


__all__ = ["redact_text", "redact_value"]
