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
import json
import os
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from praetor_engine import __version__ as _ENGINE_VERSION
from praetor_engine.audit_hash import (
    GENESIS_HASH,
    compute_hash,
)
from praetor_engine.audit_hash import (
    canonical_timestamp as _canonical_timestamp,
)
from praetor_engine.types import Decision, DecisionResult, PolicyInput
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_serializer

from praetor.errors import AuditError


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


# Canonicalization + hashing are shared with the control plane and mirrored
# by the TS SDK via praetor_engine.audit_hash, so every party recomputes the
# same bytes. (One residual cross-language gap: integral floats — Python 1.0
# vs JS 1 — since JS has no int/float distinction; avoid float-valued tool
# arguments in chains that must verify across languages.)
_compute_hash = compute_hash


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
    """Append-only JSONL with a per-(agent, session) Merkle chain.
    Thread-safe, fsync-on-append.

    Each (agent_id, session_id) is an independent chain whose seq starts at
    0 and whose first event links to `GENESIS_HASH`. This matches the
    control plane's ingestion contract, which verifies and orders events
    per (organization, agent, session) — a single file-global chain would
    make every session after the first fail ingest with a seq/prev_hash
    mismatch. Chain tips are reconstructed from the on-disk log on
    construction, so chains continue across process restarts.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        on_event: Callable[[AuditEvent], None] | None = None,
    ) -> None:
        # Accept a plain string path too — the documented quickstart passes
        # one — so `JsonlAuditSink("audit.jsonl")` doesn't crash on the first
        # `.exists()`/`.stat()` call.
        self._path = Path(path)
        self._lock = threading.Lock()
        self._on_event = on_event
        # (agent_id, session_id) -> (last_seq, last_hash)
        self._chains: dict[tuple[str, str], tuple[int, str]] = self._scan_chains()
        # seq of the most recent record() on any chain (for observability).
        self._last_seq = -1

    @property
    def path(self) -> Path:
        return self._path

    @property
    def current_seq(self) -> int:
        """Seq assigned to the most recently recorded event (any chain)."""
        return self._last_seq

    def _scan_chains(self) -> dict[tuple[str, str], tuple[int, str]]:
        chains: dict[tuple[str, str], tuple[int, str]] = {}
        if not self._path.exists() or self._path.stat().st_size == 0:
            return chains
        with open(self._path, "rb") as f:
            for raw in f:
                line = raw.decode("utf-8").rstrip("\n")
                if not line:
                    continue
                try:
                    event = AuditEvent.model_validate_json(line)
                except Exception as exc:
                    raise AuditError(f"corrupt audit log: {exc}") from exc
                chains[(event.agent_id, event.session_id)] = (event.seq, event.hash)
        return chains

    def record(
        self, policy_input: PolicyInput, decision: DecisionResult
    ) -> AuditEvent:
        with self._lock:
            key = (policy_input.agent.id, policy_input.session.id)
            last_seq, prev_hash = self._chains.get(key, (-1, GENESIS_HASH))
            next_seq = last_seq + 1
            event = _build_event(
                seq=next_seq,
                prev_hash=prev_hash,
                policy_input=policy_input,
                decision=decision,
            )
            self._append(event)
            self._chains[key] = (next_seq, event.hash)
            self._last_seq = next_seq
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
    # Independent chain state per (agent_id, session_id): the expected
    # prev_hash and the expected next seq. Events for different sessions are
    # interleaved in the file, so each is verified against its own tip.
    expected_prev: dict[tuple[str, str], str] = {}
    expected_seq: dict[tuple[str, str], int] = {}
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

            key = (raw_dict["agent_id"], raw_dict["session_id"])
            prev_for_key = expected_prev.get(key, GENESIS_HASH)
            if raw_dict["prev_hash"] != prev_for_key:
                raise AuditError(
                    f"line {line_no}: prev_hash mismatch "
                    f"(expected {prev_for_key}, got {raw_dict['prev_hash']})"
                )
            seq_for_key = expected_seq.get(key, 0)
            if raw_dict["seq"] != seq_for_key:
                raise AuditError(
                    f"line {line_no}: seq mismatch "
                    f"(expected {seq_for_key}, got {raw_dict['seq']})"
                )
            body = {k: v for k, v in raw_dict.items() if k != "hash"}
            recomputed = _compute_hash(body)
            if recomputed != stored_hash:
                raise AuditError(
                    f"line {line_no}: hash mismatch "
                    f"(recomputed {recomputed}, stored {stored_hash})"
                )
            expected_prev[key] = stored_hash
            expected_seq[key] = seq_for_key + 1
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
        # Offset is the number of events already acked, i.e. a position in the
        # append-ordered file — NOT a seq. With per-(agent, session) chains the
        # seq restarts at 0 for each session, so it is not globally monotonic
        # and cannot be used to track shipping progress across the whole file.
        self._acked_count = self._load_offset()

    @property
    def acked_count(self) -> int:
        return self._acked_count

    def _load_offset(self) -> int:
        if not self._offset_path.exists():
            return 0
        text = self._offset_path.read_text().strip()
        return int(text) if text else 0

    def _save_offset(self, count: int) -> None:
        # Write+rename for atomic offset update.
        tmp = self._offset_path.with_suffix(self._offset_path.suffix + ".tmp")
        tmp.write_text(str(count))
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
        """Synchronously ship every event past the offset. Returns count shipped."""
        shipped = 0
        for index, event in enumerate(self._read_all_events()):
            if index < self._acked_count:
                continue
            if not self._ship_with_backoff(event):
                # Shutting down before this event was acked. Do NOT advance
                # the offset, or the event is dropped: on restart the backlog
                # scan would begin after it. Leaving the offset put means it
                # is re-shipped next run (at-least-once).
                break
            self._acked_count = index + 1
            self._save_offset(self._acked_count)
            shipped += 1
        return shipped

    def _run(self) -> None:  # pragma: no cover - exercised via integration tests
        while not self._stop.is_set():
            with contextlib.suppress(Exception):
                self.ship_pending()
            self._stop.wait(self._poll)

    def _read_all_events(self) -> Iterator[AuditEvent]:
        if not self._sink.path.exists():
            return
        with open(self._sink.path) as f:
            for raw in f:
                stripped = raw.strip()
                if not stripped:
                    continue
                yield AuditEvent.model_validate_json(stripped)

    def _ship_with_backoff(self, event: AuditEvent) -> bool:
        """Ship with exponential backoff. Returns True once acked, or False if
        we were told to stop before delivery succeeded (caller must not
        advance the offset in that case)."""
        backoff = self._poll
        while not self._stop.is_set():
            try:
                self._transport.ship(event)
                return True
            except Exception:
                time.sleep(min(backoff, self._max_backoff))
                backoff = min(backoff * 2, self._max_backoff)
        return False


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
