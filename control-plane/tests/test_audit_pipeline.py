"""Async chain verification (step 2) + authoritative cold tier & replay (step 3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient
from praetor_engine.audit_hash import compute_hash as _canonical_hash
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Finding, Organization
from app.schemas import AuditEventIn
from app.services.archive import archive_pending, replay_archive
from app.services.audit_ingest import ingest_event
from app.services.audit_verify import verify_pending
from app.services.event_store import reset_event_sink
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


def _ingest(session: Session, org: Organization, event: AuditEventIn) -> AuditEvent:
    return ingest_event(session, org_id=org.id, event=event)


# --- Step 2: async verification ---------------------------------------------
def test_sync_mode_marks_verified(session: Session, org: Organization) -> None:
    row = _ingest(session, org, _ev(seq=0, prev_hash=GENESIS))
    session.commit()
    assert row.verified is True


def test_async_ingest_is_unverified_then_verifier_flips(
    monkeypatch, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "audit_async_verify", True)
    e0 = _ingest(session, org, _ev(seq=0, prev_hash=GENESIS))
    e1 = _ingest(session, org, _ev(seq=1, prev_hash=e0.hash))
    session.commit()
    assert (e0.verified, e1.verified) == (False, False)

    result = verify_pending(session, org.id)
    session.commit()
    assert result == {"verified": 2, "chains": 1, "tampered": 0}
    assert (e0.verified, e1.verified) == (True, True)

    # Idempotent: nothing left pending.
    assert verify_pending(session, org.id)["verified"] == 0


def test_verifier_pauses_on_gap(
    monkeypatch, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "audit_async_verify", True)
    e0 = _ingest(session, org, _ev(seq=0, prev_hash=GENESIS))
    # seq 1 hasn't arrived; seq 2 is here (out of order / in flight).
    e2 = _ingest(session, org, _ev(seq=2, prev_hash="a" * 64))
    session.commit()

    result = verify_pending(session, org.id)
    session.commit()
    assert result["verified"] == 1  # only seq 0
    assert e0.verified is True
    assert e2.verified is False  # waits for seq 1


def test_verifier_flags_tamper(
    monkeypatch, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "audit_async_verify", True)
    e0 = _ingest(session, org, _ev(seq=0, prev_hash=GENESIS))
    # seq 1 at the right position but linking to the WRONG prev_hash
    # (self-hash is still valid, so it passes ingest).
    e1 = _ingest(session, org, _ev(seq=1, prev_hash="b" * 64))
    session.commit()

    result = verify_pending(session, org.id)
    session.commit()
    assert result["tampered"] == 1
    assert e0.verified is True
    assert e1.verified is False

    finding = session.execute(
        select(Finding).where(Finding.rule_id == "audit-chain-integrity")
    ).scalar_one()
    assert finding.severity == "critical"
    assert finding.evidence["seq"] == 1


def test_verify_run_endpoint(client: TestClient) -> None:
    r = client.post("/telemetry/verify/run")
    assert r.status_code == 200
    assert r.json() == {"verified": 0, "chains": 0, "tampered": 0}


# --- Step 3: authoritative cold tier + replay -------------------------------
def _enable_archive(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(get_settings(), "event_archive_dir", str(tmp_path))
    reset_event_sink()


def test_archive_pending_writes_and_stamps(
    monkeypatch, tmp_path, session: Session, org: Organization
) -> None:
    _enable_archive(monkeypatch, tmp_path)
    try:
        e0 = _ingest(session, org, _ev(seq=0, prev_hash=GENESIS))
        e1 = _ingest(session, org, _ev(seq=1, prev_hash=e0.hash))
        session.commit()

        result = archive_pending(session, org.id)
        session.commit()
        assert result == {"archived": 2, "caught_up": True, "enabled": True}
        assert e0.archived_at is not None and e1.archived_at is not None

        # Second pass is a no-op — nothing left unarchived.
        assert archive_pending(session, org.id)["archived"] == 0
    finally:
        reset_event_sink()


def test_archive_noop_when_disabled(
    monkeypatch, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "event_archive_dir", "")
    reset_event_sink()
    _ingest(session, org, _ev(seq=0, prev_hash=GENESIS))
    session.commit()
    result = archive_pending(session, org.id)
    assert result == {"archived": 0, "caught_up": True, "enabled": False}
    row = session.execute(select(AuditEvent)).scalar_one()
    assert row.archived_at is None  # unstamped → archives once enabled later


def test_replay_rebuilds_hot_from_cold(
    monkeypatch, tmp_path, session: Session, org: Organization
) -> None:
    _enable_archive(monkeypatch, tmp_path)
    try:
        e0 = _ingest(session, org, _ev(seq=0, prev_hash=GENESIS))
        _ingest(session, org, _ev(seq=1, prev_hash=e0.hash))
        session.commit()
        archive_pending(session, org.id)
        session.commit()

        # Wipe the hot store; the cold tier is authoritative.
        session.execute(delete(AuditEvent).where(AuditEvent.organization_id == org.id))
        session.commit()
        assert session.execute(select(AuditEvent)).first() is None

        result = replay_archive(session, org.id)
        session.commit()
        assert result == {"read": 2, "reingested": 2, "skipped": 0}
        assert session.execute(
            select(AuditEvent).where(AuditEvent.organization_id == org.id)
        ).all()

        # Idempotent: a second replay re-ingests nothing.
        assert replay_archive(session, org.id) == {
            "read": 2,
            "reingested": 0,
            "skipped": 2,
        }
    finally:
        reset_event_sink()


def test_archive_and_replay_endpoints(
    monkeypatch, tmp_path, client: TestClient, session: Session, org: Organization
) -> None:
    _enable_archive(monkeypatch, tmp_path)
    try:
        _ingest(session, org, _ev(seq=0, prev_hash=GENESIS))
        session.commit()
        r = client.post("/telemetry/archive/run")
        assert r.status_code == 200 and r.json()["archived"] == 1
        r = client.post("/telemetry/replay")
        assert r.status_code == 200 and r.json()["read"] == 1
    finally:
        reset_event_sink()
