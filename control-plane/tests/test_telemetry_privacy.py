"""Classification-aware retention + field-level telemetry encryption, and
request-path async connector dispatch."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from praetor_engine.audit_hash import compute_hash as _canonical_hash
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import AuditEvent, Organization
from app.schemas import AuditEventIn
from app.services.audit_ingest import ingest_event
from app.services.crypto import reset_cipher
from app.services.pii import (
    CLASS_RESTRICTED,
    CLASS_STANDARD,
    classify_payload,
)
from app.services.retention import apply_retention
from app.settings import get_settings

GENESIS = "0" * 64


def _event_in(
    *,
    seq: int = 0,
    prev_hash: str = GENESIS,
    tool_arguments: dict[str, Any] | None = None,
    reason: str = "ok",
    context: dict[str, Any] | None = None,
) -> AuditEventIn:
    raw: dict[str, Any] = {
        "seq": seq,
        "timestamp": datetime(2026, 1, 1, 0, 0, seq, tzinfo=UTC).isoformat(),
        "agent_id": "agent-1",
        "session_id": "sess-1",
        "tool_name": "http.get",
        "tool_use_id": None,
        "tool_arguments": tool_arguments or {"url": "https://x"},
        "decision": "allow",
        "reason": reason,
        "matched_policy_id": "p1",
        "suggested_transform": None,
        "context": context or {},
        "evaluator_version": "0.1.0",
        "prev_hash": prev_hash,
        "hash": GENESIS,
    }
    placeholder = AuditEventIn.model_validate(raw)
    raw["hash"] = _canonical_hash(placeholder.model_dump(mode="json", exclude={"hash"}))
    return AuditEventIn.model_validate(raw)


# --- Field-level telemetry encryption ---------------------------------------
def test_payload_encrypted_at_rest_and_transparent_on_read(
    monkeypatch, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "secret_keys", [Fernet.generate_key().decode()])
    monkeypatch.setattr(get_settings(), "telemetry_field_encryption", True)
    reset_cipher()

    secret_args = {"url": "https://x", "token": "shhh-super-secret"}
    ingest_event(session, org_id=org.id, event=_event_in(tool_arguments=secret_args))
    session.commit()

    # At rest: the raw column holds a sealed envelope, not the plaintext.
    raw = session.execute(text("SELECT tool_arguments FROM audit_events")).scalar_one()
    assert "enc:v1:" in raw
    assert "shhh-super-secret" not in raw

    # On read through the ORM the plaintext dict comes back transparently.
    session.expire_all()
    row = session.execute(select(AuditEvent)).scalar_one()
    assert row.tool_arguments == secret_args

    # The detection engine reads via a bare-column select; decryption must
    # apply there too, else detections would scan ciphertext.
    col = session.execute(select(AuditEvent.tool_arguments)).scalar_one()
    assert col == secret_args


def test_payload_plaintext_when_encryption_disabled(
    session: Session, org: Organization
) -> None:
    ingest_event(
        session, org_id=org.id, event=_event_in(tool_arguments={"k": "clear-value"})
    )
    session.commit()
    raw = session.execute(text("SELECT tool_arguments FROM audit_events")).scalar_one()
    assert "enc:v1:" not in raw
    assert "clear-value" in raw


# --- Classification ---------------------------------------------------------
def test_classify_payload_detects_pii() -> None:
    assert classify_payload({"email": "alice@example.com"}) == CLASS_RESTRICTED
    assert classify_payload("no pii here", {"x": 1}) == CLASS_STANDARD


def test_ingest_classifies_when_enabled(
    monkeypatch, session: Session, org: Organization
) -> None:
    monkeypatch.setattr(get_settings(), "classify_telemetry", True)
    ingest_event(
        session,
        org_id=org.id,
        event=_event_in(tool_arguments={"email": "bob@corp.com"}),
    )
    ingest_event(
        session,
        org_id=org.id,
        event=_event_in(seq=1, prev_hash=_latest_hash(session), tool_arguments={"n": 1}),
    )
    session.commit()
    classes = sorted(
        c for (c,) in session.execute(select(AuditEvent.classification)).all()
    )
    assert classes == [CLASS_RESTRICTED, CLASS_STANDARD]


def test_ingest_defaults_standard_when_classification_off(
    session: Session, org: Organization
) -> None:
    ingest_event(
        session,
        org_id=org.id,
        event=_event_in(tool_arguments={"email": "carol@corp.com"}),
    )
    session.commit()
    row = session.execute(select(AuditEvent)).scalar_one()
    assert row.classification == CLASS_STANDARD


def _latest_hash(session: Session) -> str:
    return session.execute(
        select(AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1)
    ).scalar_one()


# --- Classification-aware retention -----------------------------------------
def _raw_event(
    session: Session, org: Organization, *, ts: datetime, classification: str, tag: str
) -> None:
    session.add(
        AuditEvent(
            organization_id=org.id,
            seq=0,
            timestamp=ts,
            agent_id="a",
            session_id=f"s-{tag}",
            tool_name="t",
            tool_arguments={},
            decision="allow",
            reason="r",
            context={},
            evaluator_version="0.1.0",
            classification=classification,
            prev_hash=GENESIS,
            hash=f"{tag:0>64}",
        )
    )


def test_retention_by_class_prunes_restricted_sooner(
    session: Session, org: Organization
) -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    _raw_event(session, org, ts=now - timedelta(days=40), classification="restricted", tag="old")
    _raw_event(session, org, ts=now - timedelta(days=10), classification="restricted", tag="new")
    _raw_event(session, org, ts=now - timedelta(days=400), classification="standard", tag="std")
    session.commit()

    # No default window; restricted events age out after 30 days.
    result = apply_retention(
        session,
        org_id=org.id,
        retention_days=None,
        retention_by_class={"restricted": 30},
        now=now,
    )
    session.commit()
    assert result["pruned"] == 1
    remaining = {
        r.session_id for r in session.execute(select(AuditEvent)).scalars()
    }
    # The 40-day restricted event is gone; the recent restricted and the old
    # standard (no default window) survive.
    assert remaining == {"s-new", "s-std"}


def test_retention_default_window_backward_compatible(
    session: Session, org: Organization
) -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    _raw_event(session, org, ts=now - timedelta(days=40), classification="standard", tag="old")
    _raw_event(session, org, ts=now - timedelta(days=5), classification="standard", tag="new")
    session.commit()
    result = apply_retention(
        session, org_id=org.id, retention_days=30, now=now
    )
    session.commit()
    assert result["pruned"] == 1
    remaining = {r.session_id for r in session.execute(select(AuditEvent)).scalars()}
    assert remaining == {"s-new"}


def test_retention_noop_when_unconfigured(
    session: Session, org: Organization
) -> None:
    result = apply_retention(session, org_id=org.id, retention_days=None)
    assert result == {"rolled": 0, "pruned": 0, "buckets": 0, "caught_up": True}


# --- Request-path async connector dispatch ----------------------------------
def test_report_finding_enqueues_dispatch(monkeypatch, client: TestClient) -> None:
    calls: list[str] = []

    class _FakeTask:
        def delay(self, finding_id: str) -> None:
            calls.append(finding_id)

    import app.routers.findings as findings_router

    monkeypatch.setattr(findings_router, "dispatch_finding_task", _FakeTask())
    r = client.post(
        "/findings/report",
        json={"observation": "suspicious base64 blob exfil attempt", "suggested_severity": "high"},
    )
    assert r.status_code == 201
    assert calls == [r.json()["id"]]


def test_dispatch_finding_task_delivers(monkeypatch, session: Session, org: Organization) -> None:
    from app.models import Finding, FindingSource
    from app.workers.tasks import dispatch_finding_task

    finding = Finding(
        organization_id=org.id,
        rule_id="agent-report",
        title="t",
        severity="high",
        category="anomaly",
        source=FindingSource.AGENT_REPORT.value,
        agent_id=None,
        session_id=None,
        dedup_key="d1",
        count=1,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        evidence={},
    )
    session.add(finding)
    session.commit()

    import app.services.forward as forward_mod
    import app.services.notify_connectors as connectors_mod

    monkeypatch.setattr(forward_mod, "forward_finding", lambda *a, **k: True)
    monkeypatch.setattr(connectors_mod, "dispatch_finding", lambda *a, **k: 2)

    result = dispatch_finding_task(finding.id)
    assert result == {"forwarded": 1, "notified": 2}

    # Unknown id is a safe no-op.
    assert dispatch_finding_task("does-not-exist") == {"forwarded": 0, "notified": 0}
