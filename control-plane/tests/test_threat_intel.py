"""Threat-intel: parsing, normalization, upsert, sync, detection, RBAC."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    AuditEvent,
    Finding,
    FindingCategory,
    Organization,
    Quarantine,
    ThreatFeed,
    ThreatIndicator,
)
from app.services.detections import run_detections
from app.services.threat_intel import (
    discover_taxii_collections,
    normalize_indicator,
    parse_feed,
    parse_stix_objects,
    poll_taxii_collection,
    sync_feed,
    upsert_indicators,
)
from app.settings import get_settings

_SEQ = [1000]


def _feed(org: Organization, fmt: str, **kw) -> ThreatFeed:
    return ThreatFeed(
        organization_id=org.id, name=kw.pop("name", f"feed-{fmt}"), format=fmt, **kw
    )


def _persisted_feed(session: Session, org: Organization, fmt: str, **kw) -> ThreatFeed:
    feed = _feed(org, fmt, **kw)
    session.add(feed)
    session.commit()
    return feed


def _audit(
    session: Session,
    org: Organization,
    *,
    tool_arguments: dict,
    tool_name: str = "http.post",
    agent_id: str = "agent-ti",
    session_id: str = "sess-ti",
) -> AuditEvent:
    _SEQ[0] += 1
    ev = AuditEvent(
        organization_id=org.id,
        seq=_SEQ[0],
        timestamp=datetime.now(UTC) - timedelta(minutes=1),
        agent_id=agent_id,
        session_id=session_id,
        tool_name=tool_name,
        tool_arguments=tool_arguments,
        decision="allow",
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


def _mock_client(body: str, status: int = 200) -> httpx.Client:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


# --- normalization ----------------------------------------------------------
def test_normalize_indicator() -> None:
    assert normalize_indicator("domain", "Evil.COM.") == "evil.com"
    assert normalize_indicator("ip", "1.2.3.4") == "1.2.3.4"
    assert normalize_indicator("ip", "999.1.1.1") is None
    assert normalize_indicator("sha256", "AB" * 32) == ("ab" * 32)
    assert normalize_indicator("sha256", "abc") is None
    assert normalize_indicator("regex", "(unbalanced") is None
    assert normalize_indicator("regex", "evil-[0-9]+") == "evil-[0-9]+"


# --- parsing ----------------------------------------------------------------
def test_parse_plaintext(org: Organization) -> None:
    feed = _feed(org, "plaintext", default_indicator_type="domain")
    drafts = parse_feed("# comment\nevil.com\n\nbad.net\n", feed)
    assert {d.value for d in drafts} == {"evil.com", "bad.net"}


def test_parse_json_objects(org: Organization) -> None:
    feed = _feed(org, "json")
    body = json.dumps(
        [{"type": "ip", "value": "9.9.9.9", "confidence": 90, "severity": "critical"}]
    )
    drafts = parse_feed(body, feed)
    assert drafts[0].type == "ip"
    assert drafts[0].confidence == 90
    assert drafts[0].severity == "critical"


def test_parse_csv(org: Organization) -> None:
    feed = _feed(org, "csv")
    drafts = parse_feed("value,type,confidence\nevil.com,domain,70\n", feed)
    assert drafts[0].type == "domain"
    assert drafts[0].confidence == 70


def test_parse_stix(org: Organization) -> None:
    feed = _feed(org, "stix")
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'evil.example']",
                "valid_until": "2030-01-01T00:00:00Z",
                "labels": ["malicious-activity"],
            },
            {
                "type": "indicator",
                "pattern": "[file:hashes.'SHA-256' = '"
                + "a" * 64
                + "']",
            },
        ],
    }
    drafts = parse_feed(json.dumps(bundle), feed)
    by_type = {d.type: d for d in drafts}
    assert by_type["domain"].value == "evil.example"
    assert by_type["sha256"].value == "a" * 64


def test_parse_misp(org: Organization) -> None:
    feed = _feed(org, "misp")
    data = {
        "response": [
            {
                "Event": {
                    "Attribute": [
                        {"type": "domain", "value": "evil.org"},
                        {"type": "ip-dst", "value": "8.8.8.8"},
                    ]
                }
            }
        ]
    }
    drafts = parse_feed(json.dumps(data), feed)
    assert {(d.type, d.value) for d in drafts} == {
        ("domain", "evil.org"),
        ("ip", "8.8.8.8"),
    }


# --- upsert -----------------------------------------------------------------
def test_upsert_dedup(session: Session, org: Organization) -> None:
    feed = _persisted_feed(session, org, "plaintext", default_indicator_type="domain")
    now = datetime.now(UTC)
    drafts = parse_feed("evil.com\nEVIL.com\nbad.net\n", feed)
    created, updated = upsert_indicators(
        session, org_id=org.id, feed=feed, drafts=drafts, now=now
    )
    session.commit()
    # evil.com and EVIL.com normalize to the same value → one create + one update.
    assert created == 2
    assert updated == 1
    count = session.query(ThreatIndicator).filter_by(organization_id=org.id).count()
    assert count == 2


# --- sync -------------------------------------------------------------------
def test_sync_remote_feed(session: Session, org: Organization) -> None:
    feed = _persisted_feed(
        session,
        org,
        "plaintext",
        default_indicator_type="domain",
        url="https://example.com/iocs.txt",
    )
    result = sync_feed(
        session, feed, http_client=_mock_client("evil.com\nbad.net\n")
    )
    session.commit()
    assert result["status"] == "ok"
    assert result["created"] == 2
    assert feed.last_status == "ok"
    assert feed.indicator_count == 2


def test_sync_blocks_ssrf(session: Session, org: Organization) -> None:
    feed = _persisted_feed(
        session,
        org,
        "plaintext",
        default_indicator_type="ip",
        url="http://169.254.169.254/latest/meta-data/",
    )
    result = sync_feed(session, feed)
    session.commit()
    assert result["status"] == "error"
    assert session.query(ThreatIndicator).count() == 0


def test_sync_manual_feed_is_noop_ok(session: Session, org: Organization) -> None:
    feed = _persisted_feed(session, org, "plaintext", default_indicator_type="domain")
    result = sync_feed(session, feed)
    assert result["status"] == "ok"


# --- detection integration --------------------------------------------------
def _add_indicator(
    session: Session,
    org: Organization,
    *,
    itype: str = "domain",
    value: str = "evil.com",
    severity: str = "high",
    expires_at: datetime | None = None,
) -> ThreatIndicator:
    now = datetime.now(UTC)
    ind = ThreatIndicator(
        organization_id=org.id,
        feed_id=None,
        type=itype,
        value=value,
        confidence=80,
        severity=severity,
        tags=[],
        references=[],
        tlp="amber",
        first_seen=now,
        last_seen=now,
        expires_at=expires_at,
    )
    session.add(ind)
    session.commit()
    return ind


def test_threat_intel_finding_raised(session: Session, org: Organization) -> None:
    _add_indicator(session, org, value="evil.com", severity="high")
    _audit(session, org, tool_arguments={"url": "https://evil.com/steal"})
    run_detections(session, org_id=org.id)
    session.commit()
    fs = [
        f
        for f in session.query(Finding).filter_by(organization_id=org.id)
        if f.rule_id == "threat-intel-match"
    ]
    assert len(fs) == 1
    assert fs[0].category == FindingCategory.THREAT_INTEL
    assert fs[0].severity == "high"
    assert fs[0].atlas_technique == "AML.T0024"
    assert fs[0].evidence["indicators"][0]["value"] == "evil.com"


def test_subdomain_matches_indicator(session: Session, org: Organization) -> None:
    _add_indicator(session, org, value="evil.com")
    _audit(session, org, tool_arguments={"host": "data.evil.com"})
    run_detections(session, org_id=org.id)
    session.commit()
    fs = [
        f
        for f in session.query(Finding).filter_by(organization_id=org.id)
        if f.rule_id == "threat-intel-match"
    ]
    assert len(fs) == 1


def test_expired_indicator_ignored(session: Session, org: Organization) -> None:
    _add_indicator(
        session,
        org,
        value="evil.com",
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    _audit(session, org, tool_arguments={"url": "https://evil.com/x"})
    run_detections(session, org_id=org.id)
    session.commit()
    fs = [
        f
        for f in session.query(Finding).filter_by(organization_id=org.id)
        if f.rule_id == "threat-intel-match"
    ]
    assert fs == []


def test_critical_indicator_auto_quarantines(
    session: Session, org: Organization
) -> None:
    org.auto_quarantine = True
    session.commit()
    _add_indicator(session, org, value="c2.evil.com", severity="critical")
    _audit(
        session,
        org,
        tool_arguments={"url": "https://c2.evil.com/beacon"},
        agent_id="agent-bad",
    )
    result = run_detections(session, org_id=org.id)
    session.commit()
    assert result["quarantined"] >= 1
    assert (
        session.query(Quarantine)
        .filter_by(organization_id=org.id, agent_id="agent-bad")
        .count()
        == 1
    )


# --- router + RBAC ----------------------------------------------------------
def test_manual_feed_and_indicator_crud(client: TestClient) -> None:
    r = client.post(
        "/threat/feeds",
        json={"name": "manual", "format": "plaintext", "default_indicator_type": "domain"},
    )
    assert r.status_code == 201
    feed_id = r.json()["id"]

    # Manual indicator, value gets normalized.
    r = client.post("/threat/indicators", json={"type": "domain", "value": "BAD.com"})
    assert r.status_code == 201
    assert r.json()["value"] == "bad.com"

    assert client.get("/threat/indicators").status_code == 200
    assert client.get("/threat/indicators?type=domain").json()[0]["value"] == "bad.com"

    # Manual feed syncs to an OK no-op.
    assert client.post(f"/threat/feeds/{feed_id}/sync").json()["status"] == "ok"


def test_invalid_indicator_rejected(client: TestClient) -> None:
    r = client.post("/threat/indicators", json={"type": "ip", "value": "not-an-ip"})
    assert r.status_code == 422


def test_feed_rejects_internal_url(client: TestClient) -> None:
    r = client.post(
        "/threat/feeds",
        json={
            "name": "ssrf",
            "format": "plaintext",
            "default_indicator_type": "ip",
            "url": "http://169.254.169.254/latest/",
        },
    )
    assert r.status_code == 422


def test_rbac_viewer_cannot_manage_feeds(
    monkeypatch, app, org: Organization
) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["ro"])
    monkeypatch.setattr(s, "api_key_orgs", {"ro": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"ro": "viewer"})

    c = TestClient(app)
    c.headers.update({"X-API-Key": "ro", "X-Org-Slug": "acme"})
    assert c.get("/threat/feeds").status_code == 200
    assert (
        c.post(
            "/threat/feeds",
            json={"name": "x", "format": "plaintext", "default_indicator_type": "domain"},
        ).status_code
        == 403
    )


# --- TAXII 2.1 --------------------------------------------------------------
def _json_client(payloads: list[dict]) -> tuple[httpx.Client, list[httpx.Request]]:
    state = {"i": 0}
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        idx = min(state["i"], len(payloads) - 1)
        state["i"] += 1
        return httpx.Response(200, json=payloads[idx])

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def _stix_indicator(pattern: str) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--00000000-0000-4000-8000-000000000000",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_until": "2030-01-01T00:00:00Z",
    }


_OBJECTS_URL = "https://example.com/api1/collections/c1/objects/"


def test_taxii_poll_single_page() -> None:
    client, _ = _json_client(
        [{"objects": [_stix_indicator("[domain-name:value = 'evil.taxii']")], "more": False}]
    )
    objs = poll_taxii_collection(_OBJECTS_URL, http_client=client)
    drafts = parse_stix_objects(objs)
    assert (drafts[0].type, drafts[0].value) == ("domain", "evil.taxii")


def test_taxii_pagination_follows_next() -> None:
    p1 = {
        "objects": [_stix_indicator("[domain-name:value = 'a.com']")],
        "more": True,
        "next": "CURSOR2",
    }
    p2 = {
        "objects": [_stix_indicator("[domain-name:value = 'b.com']")],
        "more": False,
    }
    client, seen = _json_client([p1, p2])
    objs = poll_taxii_collection(_OBJECTS_URL, http_client=client)
    assert len(objs) == 2
    # The second request carries the `next` cursor from page one.
    assert seen[1].url.params.get("next") == "CURSOR2"


def test_taxii_incremental_added_after() -> None:
    client, seen = _json_client([{"objects": [], "more": False}])
    since = datetime(2026, 7, 1, tzinfo=UTC)
    poll_taxii_collection(_OBJECTS_URL, added_after=since, http_client=client)
    assert seen[0].url.params.get("added_after", "").startswith("2026-07-01")


def test_taxii_ssrf_blocked() -> None:
    import pytest

    from app.services.egress import EgressBlocked

    client, _ = _json_client([{"objects": [], "more": False}])
    with pytest.raises(EgressBlocked):
        poll_taxii_collection(
            "http://169.254.169.254/collections/c/objects/", http_client=client
        )


def test_sync_taxii_feed(session: Session, org: Organization) -> None:
    feed = _persisted_feed(session, org, "taxii", url=_OBJECTS_URL)
    client, _ = _json_client(
        [{"objects": [_stix_indicator("[ipv4-addr:value = '5.5.5.5']")], "more": False}]
    )
    result = sync_feed(session, feed, http_client=client)
    session.commit()
    assert result["status"] == "ok"
    assert result["created"] == 1
    ind = (
        session.query(ThreatIndicator)
        .filter_by(organization_id=org.id, type="ip")
        .one()
    )
    assert ind.value == "5.5.5.5"


def test_discover_taxii_collections() -> None:
    client, _ = _json_client(
        [
            {
                "collections": [
                    {
                        "id": "c1",
                        "title": "Malware",
                        "can_read": True,
                        "media_types": ["application/stix+json;version=2.1"],
                    }
                ]
            }
        ]
    )
    cols = discover_taxii_collections("https://example.com/api1", http_client=client)
    assert cols[0]["id"] == "c1"
    assert cols[0]["objects_url"] == (
        "https://example.com/api1/collections/c1/objects/"
    )


def test_taxii_discover_endpoint_rbac_and_validation(
    monkeypatch, app, client: TestClient, org: Organization
) -> None:
    # Internal URL rejected up front (no network hit).
    r = client.post(
        "/threat/taxii/discover", json={"url": "http://169.254.169.254/api1"}
    )
    assert r.status_code == 422

    # Analyst may not discover (admin-only) — blocked before any network hit.
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["an"])
    monkeypatch.setattr(s, "api_key_orgs", {"an": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"an": "analyst"})
    c = TestClient(app)
    c.headers.update({"X-API-Key": "an", "X-Org-Slug": "acme"})
    assert (
        c.post(
            "/threat/taxii/discover", json={"url": "https://example.com/api1"}
        ).status_code
        == 403
    )
