from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from app.schemas import AuditEventIn
from app.services.audit_ingest import _canonical_hash

GENESIS = "0" * 64


def _event(
    *,
    seq: int,
    prev_hash: str,
    agent_id: str = "agent-1",
    session_id: str = "sess-1",
    tool_name: str = "http.get",
    decision: str = "allow",
    matched_policy_id: str | None = "p1",
) -> dict[str, Any]:
    raw = {
        "seq": seq,
        "timestamp": datetime(2026, 1, 1, 0, 0, seq, tzinfo=UTC).isoformat(),
        "agent_id": agent_id,
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_use_id": None,
        "tool_arguments": {"url": "https://x"},
        "decision": decision,
        "reason": "ok",
        "matched_policy_id": matched_policy_id,
        "suggested_transform": None,
        "context": {},
        "evaluator_version": "0.1.0",
        "prev_hash": prev_hash,
        "hash": "0" * 64,  # placeholder; recomputed below
    }
    # Round-trip through AuditEventIn so the hashed body matches the
    # server's serialization exactly.
    placeholder = AuditEventIn.model_validate(raw)
    body = placeholder.model_dump(mode="json", exclude={"hash"})
    raw["hash"] = _canonical_hash(body)
    return raw


def test_ingest_well_formed_event(client: TestClient) -> None:
    ev = _event(seq=0, prev_hash=GENESIS)
    r = client.post("/audit/events", json=[ev])
    assert r.status_code == 202
    assert r.json() == {"accepted": 1, "rejected": 0, "errors": []}


def test_ingest_chain_continuity(client: TestClient) -> None:
    e0 = _event(seq=0, prev_hash=GENESIS)
    r = client.post("/audit/events", json=[e0])
    assert r.json()["accepted"] == 1

    e1 = _event(seq=1, prev_hash=e0["hash"])
    r = client.post("/audit/events", json=[e1])
    assert r.json()["accepted"] == 1


def test_ingest_broken_prev_hash_rejected(client: TestClient) -> None:
    e0 = _event(seq=0, prev_hash=GENESIS)
    client.post("/audit/events", json=[e0])
    e1 = _event(seq=1, prev_hash="f" * 64)
    r = client.post("/audit/events", json=[e1])
    body = r.json()
    assert body["accepted"] == 0
    assert body["rejected"] == 1
    assert "prev_hash mismatch" in body["errors"][0]


def test_ingest_tampered_body_rejected(client: TestClient) -> None:
    ev = _event(seq=0, prev_hash=GENESIS)
    ev["reason"] = "tampered"  # hash no longer matches body
    r = client.post("/audit/events", json=[ev])
    assert r.json()["accepted"] == 0
    assert "hash mismatch" in r.json()["errors"][0]


def test_ingest_seq_must_be_sequential(client: TestClient) -> None:
    e0 = _event(seq=0, prev_hash=GENESIS)
    client.post("/audit/events", json=[e0])
    # Skip seq=1, try seq=2 -> reject.
    e2 = _event(seq=2, prev_hash=e0["hash"])
    r = client.post("/audit/events", json=[e2])
    assert r.json()["accepted"] == 0
    assert "seq mismatch" in r.json()["errors"][0]


def test_search_filters(client: TestClient) -> None:
    e0 = _event(seq=0, prev_hash=GENESIS, decision="allow", tool_name="http.get")
    e1 = _event(seq=1, prev_hash=e0["hash"], decision="deny", tool_name="http.post")
    client.post("/audit/events", json=[e0])
    client.post("/audit/events", json=[e1])

    all_events = client.get("/audit/events").json()
    assert len(all_events) == 2

    denies = client.get("/audit/events?decision=deny").json()
    assert len(denies) == 1
    assert denies[0]["decision"] == "deny"

    posts = client.get("/audit/events?tool_name=http.post").json()
    assert len(posts) == 1
    assert posts[0]["tool_name"] == "http.post"
