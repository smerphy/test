"""Durable event log + CQRS consumers + log-centric ingest (step 4)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ephorate_engine.audit_hash import compute_hash as _canonical_hash
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, MetricEvent, Organization
from app.schemas import AuditEventIn
from app.services.analytics_sink import reset_analytics_sink
from app.services.event_store import read_archive, reset_event_sink
from app.services.eventlog import (
    TOPIC_AUDIT,
    SqlEventLog,
    reset_event_log,
)
from app.services.log_pipeline import (
    GROUP_ANALYTICS,
    GROUP_HOT,
    publish_audit,
    run_all_consumers,
)
from app.settings import get_settings

GENESIS = "0" * 64


def _ev(*, seq: int, prev_hash: str, session_id: str = "s1") -> AuditEventIn:
    raw: dict[str, Any] = {
        "seq": seq,
        "timestamp": datetime(2026, 1, 1, 0, 0, seq, tzinfo=UTC).isoformat(),
        "agent_id": "agent-1",
        "session_id": session_id,
        "tool_name": "http.get",
        "tool_use_id": None,
        "tool_arguments": {"url": "https://x"},
        "decision": "allow",
        "reason": "ok",
        "matched_policy_id": "p1",
        "suggested_transform": None,
        "context": {},
        "evaluator_version": "0.1.0",
        "prev_hash": prev_hash,
        "hash": GENESIS,
    }
    placeholder = AuditEventIn.model_validate(raw)
    raw["hash"] = _canonical_hash(placeholder.model_dump(mode="json", exclude={"hash"}))
    return AuditEventIn.model_validate(raw)


# --- SqlEventLog primitive --------------------------------------------------
def test_sql_log_append_poll_commit(org: Organization) -> None:
    log = SqlEventLog()
    log.append(TOPIC_AUDIT, org.id, f"{org.id}:a:s", [{"n": 1}, {"n": 2}])

    batch = log.poll(TOPIC_AUDIT, GROUP_HOT, max_records=10)
    assert [r.payload["n"] for r in batch] == [1, 2]
    assert log.lag(TOPIC_AUDIT, GROUP_HOT) == 2

    log.commit(TOPIC_AUDIT, GROUP_HOT, batch[-1].offset)
    assert log.poll(TOPIC_AUDIT, GROUP_HOT) == []
    assert log.lag(TOPIC_AUDIT, GROUP_HOT) == 0


def test_sql_log_consumer_groups_independent(org: Organization) -> None:
    log = SqlEventLog()
    log.append(TOPIC_AUDIT, org.id, "k", [{"n": 1}])
    b = log.poll(TOPIC_AUDIT, GROUP_HOT)
    log.commit(TOPIC_AUDIT, GROUP_HOT, b[-1].offset)
    # A second group hasn't consumed anything yet — it still sees the record.
    assert len(log.poll(TOPIC_AUDIT, GROUP_ANALYTICS)) == 1


def test_commit_never_moves_backwards(org: Organization) -> None:
    log = SqlEventLog()
    log.append(TOPIC_AUDIT, org.id, "k", [{"n": 1}, {"n": 2}])
    log.commit(TOPIC_AUDIT, GROUP_HOT, 2)
    log.commit(TOPIC_AUDIT, GROUP_HOT, 1)  # stale/late commit — ignored
    assert log.lag(TOPIC_AUDIT, GROUP_HOT) == 0


# --- publish + materialize (CQRS) -------------------------------------------
def test_publish_and_materialize_to_hot_store(
    session: Session, org: Organization
) -> None:
    reset_event_log()
    e0 = _ev(seq=0, prev_hash=GENESIS)
    e1 = _ev(seq=1, prev_hash=_canonical_hash(e0.model_dump(mode="json", exclude={"hash"})))
    assert publish_audit(org.id, [e0, e1]) == 2

    # Nothing in the hot store until the consumer runs.
    assert session.execute(select(AuditEvent)).first() is None

    counts = run_all_consumers()
    assert counts[f"{TOPIC_AUDIT}:{GROUP_HOT}"] == 2
    session.expire_all()
    rows = session.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars().all()
    assert [r.seq for r in rows] == [0, 1]
    assert all(r.verified for r in rows)  # sync verify ran in the materializer


def test_materialize_is_idempotent(session: Session, org: Organization) -> None:
    reset_event_log()
    e0 = _ev(seq=0, prev_hash=GENESIS)
    publish_audit(org.id, [e0])
    publish_audit(org.id, [e0])  # duplicate ship
    run_all_consumers()
    session.expire_all()
    # Deduped on (org, hash) despite two log records.
    assert len(session.execute(select(AuditEvent)).scalars().all()) == 1


def test_analytics_consumer_writes_ndjson(
    monkeypatch, tmp_path, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "analytics_sink", "ndjson")
    monkeypatch.setattr(get_settings(), "event_archive_dir", str(tmp_path))
    reset_event_log()
    reset_analytics_sink()
    reset_event_sink()
    try:
        publish_audit(org.id, [_ev(seq=0, prev_hash=GENESIS)])
        counts = run_all_consumers()
        assert counts[f"{TOPIC_AUDIT}:{GROUP_ANALYTICS}"] == 1
        # The analytics namespace received the record.
        archived = list(read_archive("analytics_audit", org.id))
        assert len(archived) == 1 and archived[0]["seq"] == 0
    finally:
        reset_analytics_sink()
        reset_event_sink()


# --- log-centric ingest end to end ------------------------------------------
def test_ingest_via_log_endpoint(
    monkeypatch, client: TestClient, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "ingest_via_log", True)
    reset_event_log()
    e0 = _ev(seq=0, prev_hash=GENESIS)
    r = client.post("/audit/events", json=[e0.model_dump(mode="json")])
    assert r.status_code == 202
    assert r.json() == {"accepted": 1, "rejected": 0, "errors": []}

    # Accepted into the log but not yet queryable in the hot store.
    assert client.get("/audit/events").json() == []

    run_all_consumers()
    assert len(client.get("/audit/events").json()) == 1


def test_ingest_via_log_metrics(
    monkeypatch, client: TestClient, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "ingest_via_log", True)
    reset_event_log()
    metric = {
        "timestamp": datetime(2026, 1, 1, tzinfo=UTC).isoformat(),
        "agent_id": "a",
        "model": "claude-sonnet-4-6",
        "duration_ms": 10,
        "input_tokens": 5,
        "output_tokens": 3,
        "status": "success",
    }
    r = client.post("/metrics/events", json=[metric])
    assert r.status_code == 202 and r.json()["accepted"] == 1
    assert session.execute(select(MetricEvent)).first() is None
    run_all_consumers()
    session.expire_all()
    assert session.execute(select(MetricEvent)).first() is not None
