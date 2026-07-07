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

from typing import Any

# Redaction detectors live in the shared engine so the SDK (pre-hash audit
# redaction) and the control plane (finding-ingest redaction) never drift.
from ephorate_engine.redaction import redact_text, redact_value

# Data-classification labels used by classification-aware retention.
CLASS_STANDARD = "standard"
CLASS_RESTRICTED = "restricted"


def classify_payload(*values: Any) -> str:
    """Classify a set of payload values by scanning them for PII.

    Returns ``"restricted"`` if any value contains a detectable PII token
    (email, SSN, payment card, phone, secret/token), else ``"standard"``.
    Uses the shared redaction detectors so classification never drifts from
    what redaction would mask.
    """
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            _, found = redact_text(value)
        else:
            _, found = redact_value(value)
        if found:
            return CLASS_RESTRICTED
    return CLASS_STANDARD


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


__all__ = [
    "CLASS_RESTRICTED",
    "CLASS_STANDARD",
    "classify_payload",
    "redact_text",
    "redact_value",
    "scrub_subject",
]
