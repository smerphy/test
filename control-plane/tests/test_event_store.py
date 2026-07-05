"""Scale-out event store: cold archive sink, retention rollup/prune, stats."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditDailyRollup, AuditEvent, Organization
from app.services.event_store import (
    ArchiveSink,
    NullSink,
    archive_events,
    get_event_sink,
    reset_event_sink,
)
from app.services.retention import apply_retention, telemetry_stats
from app.settings import get_settings

_SEQ = [5000]


def _audit_at(
    session: Session,
    org: Organization,
    *,
    ts: datetime,
    decision: str = "allow",
    agent_id: str = "agent-1",
) -> AuditEvent:
    _SEQ[0] += 1
    ev = AuditEvent(
        organization_id=org.id,
        seq=_SEQ[0],
        timestamp=ts,
        agent_id=agent_id,
        session_id="s1",
        tool_name="http.get",
        tool_arguments={},
        decision=decision,
        reason="r",
        matched_policy_id=None,
        context={},
        evaluator_version="0.1.0",
        prev_hash="0" * 64,
        hash=f"{_SEQ[0]:064d}",
    )
    session.add(ev)
    session.commit()
    return ev


# --- archive sink -----------------------------------------------------------
def test_archive_sink_writes_partitioned_gzip(tmp_path: Path) -> None:
    sink = ArchiveSink(str(tmp_path), gzip_enabled=True)
    now = datetime(2026, 7, 5, 12, 0, 0)
    n = sink.archive("audit", "org-abc", [{"a": 1}, {"a": 2}], now)
    assert n == 2
    path = (
        tmp_path
        / "audit"
        / "org=org-abc"
        / "date=2026-07-05"
        / "audit-2026-07-05.ndjson.gz"
    )
    assert path.exists()
    with gzip.open(path, "rt") as fh:
        rows = [json.loads(line) for line in fh]
    assert rows == [{"a": 1}, {"a": 2}]


def test_archive_sink_appends(tmp_path: Path) -> None:
    sink = ArchiveSink(str(tmp_path), gzip_enabled=False)
    now = datetime(2026, 7, 5, 12, 0, 0)
    sink.archive("metric", "o1", [{"x": 1}], now)
    sink.archive("metric", "o1", [{"x": 2}], now)
    path = (
        tmp_path / "metric" / "org=o1" / "date=2026-07-05" / "metric-2026-07-05.ndjson"
    )
    lines = path.read_text().strip().splitlines()
    assert [json.loads(x)["x"] for x in lines] == [1, 2]


def test_get_event_sink_selects_by_config(monkeypatch, tmp_path: Path) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "event_archive_dir", "")
    reset_event_sink()
    assert isinstance(get_event_sink(), NullSink)
    assert get_event_sink().enabled is False

    monkeypatch.setattr(s, "event_archive_dir", str(tmp_path))
    reset_event_sink()
    sink = get_event_sink()
    assert isinstance(sink, ArchiveSink)

    # archive_events routes through the configured sink.
    assert archive_events("audit", "org-z", [{"k": "v"}]) == 1
    reset_event_sink()


def test_archive_events_noop_when_disabled(monkeypatch) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "event_archive_dir", "")
    reset_event_sink()
    assert archive_events("audit", "o", [{"k": "v"}]) == 0
    reset_event_sink()


# --- retention --------------------------------------------------------------
def test_retention_rolls_up_and_prunes(session: Session, org: Organization) -> None:
    now = datetime.now(UTC)
    old = now - timedelta(days=40)
    # Two old denies + one old allow (roll up + prune); one recent (keep).
    _audit_at(session, org, ts=old, decision="deny")
    _audit_at(session, org, ts=old, decision="deny")
    _audit_at(session, org, ts=old, decision="allow")
    _audit_at(session, org, ts=now - timedelta(days=1), decision="allow")

    result = apply_retention(
        session, org_id=org.id, retention_days=30, now=now
    )
    session.commit()

    assert result["rolled"] == 3
    assert result["pruned"] == 3
    assert result["caught_up"] is True

    # Only the recent event remains raw.
    remaining = session.query(AuditEvent).filter_by(organization_id=org.id).count()
    assert remaining == 1

    rollups = {
        (r.decision): r.count
        for r in session.query(AuditDailyRollup).filter_by(organization_id=org.id)
    }
    assert rollups == {"deny": 2, "allow": 1}


def test_retention_disabled_is_noop(session: Session, org: Organization) -> None:
    _audit_at(session, org, ts=datetime.now(UTC) - timedelta(days=100))
    result = apply_retention(session, org_id=org.id, retention_days=None)
    assert result == {"rolled": 0, "pruned": 0, "buckets": 0, "caught_up": True}
    assert session.query(AuditEvent).count() == 1


def test_retention_is_idempotent(session: Session, org: Organization) -> None:
    now = datetime.now(UTC)
    _audit_at(session, org, ts=now - timedelta(days=40), decision="deny")
    apply_retention(session, org_id=org.id, retention_days=30, now=now)
    session.commit()
    # Second pass finds nothing left to roll.
    again = apply_retention(session, org_id=org.id, retention_days=30, now=now)
    assert again["rolled"] == 0
    assert (
        session.query(AuditDailyRollup)
        .filter_by(organization_id=org.id, decision="deny")
        .one()
        .count
        == 1
    )


def test_telemetry_stats(session: Session, org: Organization) -> None:
    now = datetime.now(UTC)
    _audit_at(session, org, ts=now - timedelta(days=40), decision="deny")
    _audit_at(session, org, ts=now - timedelta(days=1), decision="allow")
    apply_retention(session, org_id=org.id, retention_days=30, now=now)
    session.commit()

    stats = telemetry_stats(session, org.id)
    assert stats["hot_audit_events"] == 1
    assert stats["rollup_events_total"] == 1
    assert stats["rollup_days"] == 1


# --- router + RBAC ----------------------------------------------------------
def test_stats_endpoint(client: TestClient) -> None:
    r = client.get("/telemetry/stats")
    assert r.status_code == 200
    body = r.json()
    assert "hot_audit_events" in body
    assert "archive_enabled" in body


def test_retention_run_requires_admin(
    monkeypatch, app, org: Organization
) -> None:
    from app.settings import get_settings as gs

    s = gs()
    monkeypatch.setattr(s, "api_keys", ["an"])
    monkeypatch.setattr(s, "api_key_orgs", {"an": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"an": "analyst"})

    c = TestClient(app)
    c.headers.update({"X-API-Key": "an", "X-Org-Slug": "acme"})
    assert c.post("/telemetry/retention/run").status_code == 403


def test_retention_run_endpoint(
    monkeypatch, client: TestClient, session: Session, org: Organization
) -> None:
    _audit_at(session, org, ts=datetime.now(UTC) - timedelta(days=40), decision="deny")
    s = get_settings()
    monkeypatch.setattr(s, "audit_retention_days", 30)
    r = client.post("/telemetry/retention/run")
    assert r.status_code == 200
    assert r.json()["pruned"] == 1
