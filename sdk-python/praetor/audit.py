"""Tamper-evident audit log.

Local format: append-only JSONL, one `AuditEvent` per line, fsync-on-append.
Each event embeds the SHA-256 hash of the previous event (Merkle chain),
so any tampering with prior entries breaks verification of every later
entry. The first event chains from `GENESIS_HASH`.

Shipping (control-plane sink) is streaming + at-least-once: the local
JSONL is the source of truth; a background `RemoteShipper` thread tails
it and POSTs each event individually, advancing a `.offset` sidecar
only on ack. Network failures back off but never drop events.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol

from praetor_engine import __version__ as _ENGINE_VERSION
from praetor_engine.types import Decision, DecisionResult, PolicyInput
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_serializer

from praetor.errors import AuditError

GENESIS_HASH: Final[str] = "0" * 64
"""SHA-256 placeholder used as the prev_hash of the first event in a log."""


def _canonical_timestamp(value: datetime) -> str:
    """Canonical wire format: `YYYY-MM-DDTHH:MM:SS.sssZ` (ms precision, Z suffix).

    Matches `Date.prototype.toISOString()` in JavaScript so audit chains
    are cross-language verifiable.
    """
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    aware = value.astimezone(UTC)
    ms = aware.microsecond // 1000
    return f"{aware.strftime('%Y-%m-%dT%H:%M:%S')}.{ms:03d}Z"


class AuditEvent(BaseModel):
    """One audit log entry. Frozen + extra=forbid for tamper-evident serialization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int = Field(..., ge=0)
    timestamp: AwareDatetime
    agent_id: str
    session_id: str
    tool_name: str
    tool_arguments: dict[str, Any]
    tool_use_id: str | None
    decision: Decision
    reason: str
    matched_policy_id: str | None
    suggested_transform: dict[str, Any] | None
    context: dict[str, Any]
    evaluator_version: str
    prev_hash: str = Field(..., min_length=64, max_length=64)
    hash: str = Field(..., min_length=64, max_length=64)

    @field_serializer("timestamp")
    def _serialize_timestamp(self, value: datetime) -> str:
        return _canonical_timestamp(value)


def _canonical_bytes_for_hashing(event_minus_hash: dict[str, Any]) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, UTF-8.

    Same algorithm in both Python and TS SDKs. Hashing over this shape
    rather than over the in-memory model means cross-language chain
    verification works as long as both writers use the same canonical
    timestamp / scalar serialization.
    """
    return json.dumps(
        event_minus_hash, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _compute_hash(event_dict_minus_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes_for_hashing(event_dict_minus_hash)).hexdigest()


class AuditSink(Protocol):
    """A sink that durably records each decision."""

    def record(
        self, policy_input: PolicyInput, decision: DecisionResult
    ) -> AuditEvent: ...

    def close(self) -> None: ...


class NullAuditSink:
    """Drops events. Useful for tests and the "disabled" mode."""

    def record(
        self, policy_input: PolicyInput, decision: DecisionResult
    ) -> AuditEvent:
        return _build_event(
            seq=0,
            prev_hash=GENESIS_HASH,
            policy_input=policy_input,
            decision=decision,
        )

    def close(self) -> None:
        return None


_HASH_PLACEHOLDER = "0" * 64


def _build_event(
    *,
    seq: int,
    prev_hash: str,
    policy_input: PolicyInput,
    decision: DecisionResult,
    now: datetime | None = None,
) -> AuditEvent:
    timestamp = now or datetime.now(UTC)
    # Build the body as a plain dict with canonical wire-format values.
    # Hashing over this dict directly (rather than re-serializing a
    # Pydantic model) keeps the hash language-agnostic: any writer that
    # produces the same canonical JSON gets the same hash.
    body: dict[str, Any] = {
        "seq": seq,
        "timestamp": _canonical_timestamp(timestamp),
        "agent_id": policy_input.agent.id,
        "session_id": policy_input.session.id,
        "tool_name": policy_input.tool.name,
        "tool_arguments": policy_input.tool.arguments,
        "tool_use_id": policy_input.tool.tool_use_id,
        "decision": decision.decision.value,
        "reason": decision.reason,
        "matched_policy_id": decision.matched_policy_id,
        "suggested_transform": decision.suggested_transform,
        "context": policy_input.context,
        "evaluator_version": _ENGINE_VERSION,
        "prev_hash": prev_hash,
    }
    body["hash"] = _compute_hash({k: v for k, v in body.items() if k != "hash"})
    return AuditEvent.model_validate(body)


class JsonlAuditSink:
    """Append-only JSONL with Merkle chain. Thread-safe, fsync-on-append.

    Resumes from the on-disk tail on construction, so the chain continues
    across process restarts.
    """

    def __init__(
        self,
        path: Path,
        *,
        on_event: Callable[[AuditEvent], None] | None = None,
    ) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._on_event = on_event
        self._seq, self._prev_hash = self._scan_tail()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def current_seq(self) -> int:
        return self._seq

    def _scan_tail(self) -> tuple[int, str]:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return (-1, GENESIS_HASH)
        last_line = ""
        with open(self._path, "rb") as f:
            for raw in f:
                line = raw.decode("utf-8").rstrip("\n")
                if line:
                    last_line = line
        if not last_line:
            return (-1, GENESIS_HASH)
        try:
            event = AuditEvent.model_validate_json(last_line)
        except Exception as exc:
            raise AuditError(f"corrupt audit log tail: {exc}") from exc
        return (event.seq, event.hash)

    def record(
        self, policy_input: PolicyInput, decision: DecisionResult
    ) -> AuditEvent:
        with self._lock:
            next_seq = self._seq + 1
            event = _build_event(
                seq=next_seq,
                prev_hash=self._prev_hash,
                policy_input=policy_input,
                decision=decision,
            )
            self._append(event)
            self._seq = next_seq
            self._prev_hash = event.hash
            if self._on_event is not None:
                with contextlib.suppress(Exception):
                    self._on_event(event)
            return event

    def _append(self, event: AuditEvent) -> None:
        line = event.model_dump_json() + "\n"
        # O_APPEND for atomic appends across processes; fsync for durability.
        fd = os.open(
            self._path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def close(self) -> None:
        return None


def verify_chain(path: Path) -> int:
    """Replay the chain and return the verified event count.

    Hashes the raw on-wire JSON (minus the `hash` field), so a chain
    produced by any conformant SDK (Python, TypeScript, …) verifies
    here as long as both writers use the same canonical-JSON convention.

    Raises `AuditError` on the first integrity violation (broken link,
    recomputed-hash mismatch, or invalid shape).
    """
    count = 0
    expected_prev = GENESIS_HASH
    if not path.exists():
        return 0
    with open(path) as f:
        for line_no, raw_line in enumerate(f, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                raw_dict = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise AuditError(f"line {line_no}: invalid JSON: {exc}") from exc
            if not isinstance(raw_dict, dict) or "hash" not in raw_dict:
                raise AuditError(f"line {line_no}: not an audit event object")

            stored_hash = raw_dict["hash"]
            # Validate shape — rejects unknown fields, wrong types, etc.
            try:
                AuditEvent.model_validate(raw_dict)
            except Exception as exc:
                raise AuditError(f"line {line_no}: invalid event shape: {exc}") from exc

            if raw_dict["prev_hash"] != expected_prev:
                raise AuditError(
                    f"line {line_no}: prev_hash mismatch "
                    f"(expected {expected_prev}, got {raw_dict['prev_hash']})"
                )
            body = {k: v for k, v in raw_dict.items() if k != "hash"}
            recomputed = _compute_hash(body)
            if recomputed != stored_hash:
                raise AuditError(
                    f"line {line_no}: hash mismatch "
                    f"(recomputed {recomputed}, stored {stored_hash})"
                )
            expected_prev = stored_hash
            count += 1
    return count


class Transport(Protocol):
    """Ships a single event to the control plane. Returns on ack; raises on failure."""

    def ship(self, event: AuditEvent) -> None: ...


class RemoteShipper:
    """Background tail-and-ship for at-least-once delivery.

    Local JSONL is the source of truth. Offset file tracks the last
    successfully-acked seq. Network failures back off exponentially but
    never drop. On startup, ships any backlog from `offset+1` to the
    current tail before resuming live shipping.
    """

    def __init__(
        self,
        sink: JsonlAuditSink,
        transport: Transport,
        offset_path: Path,
        *,
        max_backoff_seconds: float = 30.0,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        self._sink = sink
        self._transport = transport
        self._offset_path = offset_path
        self._max_backoff = max_backoff_seconds
        self._poll = poll_interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_acked_seq = self._load_offset()

    @property
    def last_acked_seq(self) -> int:
        return self._last_acked_seq

    def _load_offset(self) -> int:
        if not self._offset_path.exists():
            return -1
        text = self._offset_path.read_text().strip()
        return int(text) if text else -1

    def _save_offset(self, seq: int) -> None:
        # Write+rename for atomic offset update.
        tmp = self._offset_path.with_suffix(self._offset_path.suffix + ".tmp")
        tmp.write_text(str(seq))
        os.replace(tmp, self._offset_path)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="praetor-audit-shipper", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float | None = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def ship_pending(self) -> int:
        """Synchronously ship every event newer than the offset. Returns count shipped."""
        shipped = 0
        for event in self._read_events_after(self._last_acked_seq):
            self._ship_with_backoff(event)
            self._last_acked_seq = event.seq
            self._save_offset(event.seq)
            shipped += 1
        return shipped

    def _run(self) -> None:  # pragma: no cover - exercised via integration tests
        while not self._stop.is_set():
            with contextlib.suppress(Exception):
                self.ship_pending()
            self._stop.wait(self._poll)

    def _read_events_after(self, seq: int) -> Iterator[AuditEvent]:
        if not self._sink.path.exists():
            return
        with open(self._sink.path) as f:
            for raw in f:
                stripped = raw.strip()
                if not stripped:
                    continue
                event = AuditEvent.model_validate_json(stripped)
                if event.seq > seq:
                    yield event

    def _ship_with_backoff(self, event: AuditEvent) -> None:
        backoff = self._poll
        while not self._stop.is_set():
            try:
                self._transport.ship(event)
                return
            except Exception:
                time.sleep(min(backoff, self._max_backoff))
                backoff = min(backoff * 2, self._max_backoff)


__all__ = [
    "GENESIS_HASH",
    "AuditEvent",
    "AuditSink",
    "JsonlAuditSink",
    "NullAuditSink",
    "RemoteShipper",
    "Transport",
    "verify_chain",
]
