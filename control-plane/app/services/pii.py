"""PII detection, redaction, and subject erasure.

Redaction masks common sensitive tokens (emails, SSNs, payment cards, secrets,
tokens) in free-text before storage — applied to the richest PII sink,
agent-reported finding observations, *before* the text is even shown to the AI
triage panel. Erasure (right-to-be-forgotten) scrubs a subject's identifier
from the mutable stores in place.

Note on audit events: their `tool_arguments` are covered by the tamper-evident
hash chain, so redacting them server-side would break verification — that
redaction must happen client-side (pre-hash) in the SDK. This module therefore
targets the non-hashed stores.
"""

from __future__ import annotations

import re
from typing import Any

# --- detectors --------------------------------------------------------------
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")
_PHONE = re.compile(r"\b(?:\+?\d{1,2}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b")
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

    # Payment cards: only redact Luhn-valid runs.
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
        red, types = redact_text(value)
        return red, types
    if isinstance(value, dict):
        out_d: dict[Any, Any] = {}
        for k, v in value.items():
            rv, t = redact_value(v)
            out_d[k] = rv
            found |= t
        return out_d, found
    if isinstance(value, list):
        out_l = []
        for v in value:
            rv, t = redact_value(v)
            out_l.append(rv)
            found |= t
        return out_l, found
    return value, found


def scrub_subject(value: Any, subject: str) -> tuple[Any, int]:
    """Replace every occurrence of `subject` in a JSON-like structure with an
    erasure marker. Returns (value, replacement count)."""
    count = 0
    if not subject:
        return value, 0
    if isinstance(value, str):
        if subject in value:
            count = value.count(subject)
            return value.replace(subject, "[ERASED]"), count
        return value, 0
    if isinstance(value, dict):
        out_d: dict[Any, Any] = {}
        for k, v in value.items():
            sv, c = scrub_subject(v, subject)
            out_d[k] = sv
            count += c
        return out_d, count
    if isinstance(value, list):
        out_l = []
        for v in value:
            sv, c = scrub_subject(v, subject)
            out_l.append(sv)
            count += c
        return out_l, count
    return value, 0


__all__ = ["redact_text", "redact_value", "scrub_subject"]
