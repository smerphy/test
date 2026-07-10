"""Group-commit local sink + batched remote shipping."""

from __future__ import annotations

from pathlib import Path

from ephorate_engine.types import (
    AgentInfo,
    Decision,
    DecisionResult,
    PolicyInput,
    SessionInfo,
    ToolCall,
)

from ephorate.audit import JsonlAuditSink, RemoteShipper, verify_chain

_DECISION = DecisionResult(decision=Decision.ALLOW, reason="ok", matched_policy_id="p1")


def _pi(session: str = "s") -> PolicyInput:
    return PolicyInput(
        agent=AgentInfo(id="a"),
        tool=ToolCall(name="t"),
        session=SessionInfo(id=session),
    )


def _record(sink: JsonlAuditSink, n: int) -> None:
    for _ in range(n):
        sink.record(_pi(), _DECISION)


class _BatchCapture:
    def __init__(self) -> None:
        self.batches: list[list] = []

    def ship_batch(self, events: list) -> None:
        self.batches.append(list(events))

    def ship(self, event) -> None:  # pragma: no cover - batch path preferred
        raise AssertionError("ship_batch should be preferred")


class _SingleCapture:
    """A Transport that only implements ship() — exercises the fallback."""

    def __init__(self) -> None:
        self.events: list = []

    def ship(self, event) -> None:
        self.events.append(event)


# --- group commit -----------------------------------------------------------
def test_group_commit_writes_and_verifies_all(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "a.jsonl", group_commit=3)
    _record(sink, 5)
    sink.close()  # flushes the group-commit tail
    # Every event is durably written and the chain still verifies.
    assert verify_chain(tmp_path / "a.jsonl") == 5


def test_group_commit_default_is_per_event(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "a.jsonl")
    assert sink._group_commit == 1
    _record(sink, 2)
    assert verify_chain(tmp_path / "a.jsonl") == 2


# --- batched shipping -------------------------------------------------------
def test_ships_in_batches(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "a.jsonl")
    _record(sink, 5)
    transport = _BatchCapture()
    shipper = RemoteShipper(
        sink, transport, offset_path=tmp_path / "a.offset", batch_size=2
    )
    assert shipper.ship_pending() == 5
    assert [len(b) for b in transport.batches] == [2, 2, 1]
    assert shipper.acked_count == 5
    # Offset persisted so a restart re-ships nothing.
    assert (tmp_path / "a.offset").read_text().strip() == "5"
    assert shipper.ship_pending() == 0


def test_batch_shipping_resumes_from_offset(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "a.jsonl")
    _record(sink, 3)
    (tmp_path / "a.offset").write_text("1")  # pretend 1 already acked
    transport = _BatchCapture()
    shipper = RemoteShipper(
        sink, transport, offset_path=tmp_path / "a.offset", batch_size=10
    )
    assert shipper.ship_pending() == 2
    assert sum(len(b) for b in transport.batches) == 2


def test_ship_pending_falls_back_to_per_event(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "a.jsonl")
    _record(sink, 3)
    transport = _SingleCapture()
    shipper = RemoteShipper(
        sink, transport, offset_path=tmp_path / "a.offset", batch_size=2
    )
    assert shipper.ship_pending() == 3
    assert len(transport.events) == 3
