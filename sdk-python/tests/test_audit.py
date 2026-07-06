from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from praetor_engine.types import (
    AgentInfo,
    Decision,
    DecisionResult,
    PolicyInput,
    SessionInfo,
    ToolCall,
)

from praetor.audit import (
    GENESIS_HASH,
    AuditEvent,
    JsonlAuditSink,
    RemoteShipper,
    Transport,
    _build_event,
    verify_chain,
)
from praetor.errors import AuditError


def _pi(tool_name: str = "http.get") -> PolicyInput:
    return PolicyInput(
        agent=AgentInfo(id="agent-1"),
        tool=ToolCall(name=tool_name, arguments={"url": "https://x"}),
        session=SessionInfo(
            id="s1", started_at=datetime(2026, 1, 1, tzinfo=UTC)
        ),
    )


def _allow() -> DecisionResult:
    return DecisionResult(
        decision=Decision.ALLOW, reason="ok", matched_policy_id="p1"
    )


class TestJsonlSinkChain:
    def test_first_event_chains_from_genesis(self, tmp_path: Path) -> None:
        sink = JsonlAuditSink(tmp_path / "audit.jsonl")
        event = sink.record(_pi(), _allow())
        assert event.seq == 0
        assert event.prev_hash == GENESIS_HASH
        assert event.hash != GENESIS_HASH

    def test_independent_chains_per_agent_session(self, tmp_path: Path) -> None:
        # Two sessions interleaved in one file each get their own chain:
        # seq restarts at 0 and the first event of each links to genesis.
        # This is what lets the control plane (which verifies per
        # (org, agent, session)) ingest the log without a seq mismatch.
        path = tmp_path / "audit.jsonl"
        sink = JsonlAuditSink(path)

        def _pi_for(agent: str, session: str) -> PolicyInput:
            return PolicyInput(
                agent=AgentInfo(id=agent),
                tool=ToolCall(name="http.get", arguments={"url": "https://x"}),
                session=SessionInfo(id=session, started_at=datetime(2026, 1, 1, tzinfo=UTC)),
            )

        a0 = sink.record(_pi_for("agent-A", "s1"), _allow())
        b0 = sink.record(_pi_for("agent-B", "s2"), _allow())  # different chain
        a1 = sink.record(_pi_for("agent-A", "s1"), _allow())
        b1 = sink.record(_pi_for("agent-B", "s2"), _allow())

        assert (a0.seq, a1.seq) == (0, 1)
        assert (b0.seq, b1.seq) == (0, 1)  # restarts at 0 for the second chain
        assert a0.prev_hash == GENESIS_HASH
        assert b0.prev_hash == GENESIS_HASH  # not chained off agent-A's event
        assert a1.prev_hash == a0.hash
        assert b1.prev_hash == b0.hash
        # The interleaved file verifies as four events across two chains.
        assert verify_chain(path) == 4

    def test_accepts_str_path(self, tmp_path: Path) -> None:
        # The documented quickstart passes a plain string.
        sink = JsonlAuditSink(str(tmp_path / "audit.jsonl"))
        sink.record(_pi(), _allow())
        assert verify_chain(sink.path) == 1

    def test_non_ascii_arguments_hash_as_utf8(self, tmp_path: Path) -> None:
        # Canonical bytes must be raw UTF-8 (ensure_ascii=False) so the chain
        # is cross-language verifiable with the TS SDK's JSON.stringify.
        path = tmp_path / "audit.jsonl"
        sink = JsonlAuditSink(path)
        pi = PolicyInput(
            agent=AgentInfo(id="agent-1"),
            tool=ToolCall(name="http.get", arguments={"note": "café ☕"}),
            session=SessionInfo(id="s1", started_at=datetime(2026, 1, 1, tzinfo=UTC)),
        )
        sink.record(pi, _allow())
        raw = path.read_bytes()
        assert "café".encode() in raw  # stored as UTF-8, not \uXXXX-escaped
        assert verify_chain(path) == 1

    def test_chain_advances_across_appends(self, tmp_path: Path) -> None:
        sink = JsonlAuditSink(tmp_path / "audit.jsonl")
        e0 = sink.record(_pi(), _allow())
        e1 = sink.record(_pi("fs.read"), _allow())
        assert e1.seq == 1
        assert e1.prev_hash == e0.hash

    def test_resumes_from_tail_on_restart(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        s1 = JsonlAuditSink(path)
        s1.record(_pi(), _allow())
        s1.record(_pi("fs.read"), _allow())

        s2 = JsonlAuditSink(path)
        e2 = s2.record(_pi("net.dns"), _allow())
        assert e2.seq == 2

    def test_file_is_jsonl(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JsonlAuditSink(path)
        sink.record(_pi(), _allow())
        sink.record(_pi(), _allow())
        lines = path.read_text().splitlines()
        assert len(lines) == 2
        for line in lines:
            json.loads(line)  # each line is valid JSON

    def test_concurrent_appends_preserve_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JsonlAuditSink(path)

        def worker() -> None:
            for _ in range(10):
                sink.record(_pi(), _allow())

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert verify_chain(path) == 40

    def test_on_event_callback_fires(self, tmp_path: Path) -> None:
        captured: list[AuditEvent] = []
        sink = JsonlAuditSink(
            tmp_path / "audit.jsonl", on_event=captured.append
        )
        sink.record(_pi(), _allow())
        sink.record(_pi(), _allow())
        assert len(captured) == 2

    def test_on_event_callback_failure_does_not_break_append(
        self, tmp_path: Path
    ) -> None:
        def explode(_: AuditEvent) -> None:
            raise RuntimeError("kaboom")

        sink = JsonlAuditSink(tmp_path / "audit.jsonl", on_event=explode)
        # Must not raise; the append must still succeed.
        sink.record(_pi(), _allow())
        assert sink.current_seq == 0


class TestVerifyChain:
    def test_empty_file_returns_zero(self, tmp_path: Path) -> None:
        assert verify_chain(tmp_path / "missing.jsonl") == 0

    def test_well_formed_chain_verifies(self, tmp_path: Path) -> None:
        sink = JsonlAuditSink(tmp_path / "audit.jsonl")
        for _ in range(5):
            sink.record(_pi(), _allow())
        assert verify_chain(sink.path) == 5

    def test_tampered_prev_hash_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JsonlAuditSink(path)
        sink.record(_pi(), _allow())
        sink.record(_pi(), _allow())

        lines = path.read_text().splitlines()
        # Mutate the second event's prev_hash to break the link.
        e1 = json.loads(lines[1])
        e1["prev_hash"] = "f" * 64
        lines[1] = json.dumps(e1)
        path.write_text("\n".join(lines) + "\n")

        with pytest.raises(AuditError, match="prev_hash mismatch"):
            verify_chain(path)

    def test_tampered_body_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JsonlAuditSink(path)
        sink.record(_pi(), _allow())

        lines = path.read_text().splitlines()
        e0 = json.loads(lines[0])
        e0["reason"] = "tampered"  # hash field unchanged
        lines[0] = json.dumps(e0)
        path.write_text("\n".join(lines) + "\n")

        with pytest.raises(AuditError, match="hash mismatch"):
            verify_chain(path)


class _CountingTransport:
    def __init__(self, *, fail_first_n: int = 0) -> None:
        self.shipped: list[AuditEvent] = []
        self._remaining_failures = fail_first_n

    def ship(self, event: AuditEvent) -> None:
        if self._remaining_failures > 0:
            self._remaining_failures -= 1
            raise ConnectionError("simulated network blip")
        self.shipped.append(event)


class TestRemoteShipper:
    def test_synchronous_ship_pending(self, tmp_path: Path) -> None:
        sink = JsonlAuditSink(tmp_path / "audit.jsonl")
        sink.record(_pi(), _allow())
        sink.record(_pi("fs.read"), _allow())

        transport: Transport = _CountingTransport()
        shipper = RemoteShipper(
            sink, transport, offset_path=tmp_path / "audit.offset"
        )

        assert shipper.ship_pending() == 2
        assert shipper.acked_count == 2
        assert len(transport.shipped) == 2  # type: ignore[attr-defined]

    def test_offset_persists_across_restart(self, tmp_path: Path) -> None:
        sink = JsonlAuditSink(tmp_path / "audit.jsonl")
        sink.record(_pi(), _allow())
        sink.record(_pi(), _allow())

        offset = tmp_path / "audit.offset"
        transport_a: Transport = _CountingTransport()
        RemoteShipper(sink, transport_a, offset_path=offset).ship_pending()

        # Append more events, then a fresh shipper should only ship the new ones.
        sink.record(_pi("net.dns"), _allow())
        transport_b = _CountingTransport()
        new_shipper = RemoteShipper(sink, transport_b, offset_path=offset)
        assert new_shipper.acked_count == 2
        assert new_shipper.ship_pending() == 1
        assert len(transport_b.shipped) == 1
        assert transport_b.shipped[0].seq == 2

    def test_shutdown_mid_backoff_does_not_drop_event(self, tmp_path: Path) -> None:
        # If shutdown is signalled while an event is stuck in backoff, the
        # offset must NOT advance past it — the event has to survive to the
        # next run (at-least-once).
        sink = JsonlAuditSink(tmp_path / "audit.jsonl")
        sink.record(_pi(), _allow())
        offset = tmp_path / "audit.offset"

        # A transport that always fails, with stop already set so the backoff
        # loop exits immediately without delivering.
        always_fail = _CountingTransport(fail_first_n=10_000)
        shipper = RemoteShipper(
            sink, always_fail, offset_path=offset, poll_interval_seconds=0.001
        )
        shipper.stop()  # signal shutdown before shipping
        assert shipper.ship_pending() == 0
        assert shipper.acked_count == 0
        assert len(always_fail.shipped) == 0

        # A fresh shipper on the same offset re-ships the undelivered event.
        good = _CountingTransport()
        resumed = RemoteShipper(sink, good, offset_path=offset)
        assert resumed.ship_pending() == 1
        assert good.shipped[0].seq == 0

    def test_backoff_retries_until_success(self, tmp_path: Path) -> None:
        sink = JsonlAuditSink(tmp_path / "audit.jsonl")
        sink.record(_pi(), _allow())
        transport = _CountingTransport(fail_first_n=2)
        shipper = RemoteShipper(
            sink,
            transport,
            offset_path=tmp_path / "audit.offset",
            poll_interval_seconds=0.001,
            max_backoff_seconds=0.01,
        )
        assert shipper.ship_pending() == 1
        assert len(transport.shipped) == 1


class TestBuildEventDirect:
    def test_canonical_hash_is_stable(self) -> None:
        ev1 = _build_event(
            seq=0,
            prev_hash=GENESIS_HASH,
            policy_input=_pi(),
            decision=_allow(),
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        ev2 = _build_event(
            seq=0,
            prev_hash=GENESIS_HASH,
            policy_input=_pi(),
            decision=_allow(),
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        assert ev1.hash == ev2.hash
