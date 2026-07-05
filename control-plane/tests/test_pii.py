"""PII controls: redaction on ingest and delete-by-subject erasure."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import ApprovalRequest, ApprovalStatus, Finding, Organization
from app.services.erasure import erase_subject
from app.services.pii import redact_text, scrub_subject


# --- redaction --------------------------------------------------------------
def test_redact_common_pii() -> None:
    red, types = redact_text(
        "contact alice@acme.com or 555-123-4567, ssn 123-45-6789, "
        "key AKIAIOSFODNN7EXAMPLE"
    )
    assert "alice@acme.com" not in red
    assert "123-45-6789" not in red
    assert "AKIAIOSFODNN7EXAMPLE" not in red
    assert {"email", "ssn", "aws_key"} <= types


def test_redact_card_luhn_only() -> None:
    # Valid Visa test number (Luhn-valid) is redacted...
    red, types = redact_text("card 4111111111111111 here")
    assert "4111111111111111" not in red
    assert "card" in types
    # ...a random 16-digit non-Luhn number is left alone.
    _red2, types2 = redact_text("id 1234567812345670000")
    assert "card" not in types2


def test_redact_leaves_clean_text() -> None:
    red, types = redact_text("agent tried to read /etc/passwd via shell.exec")
    assert types == set()
    assert red == "agent tried to read /etc/passwd via shell.exec"


def test_report_redacts_when_enabled(
    session: Session, org: Organization, client: TestClient
) -> None:
    org.pii_redaction_enabled = True
    session.commit()
    r = client.post(
        "/findings/report",
        json={"observation": "leaked cred for bob@corp.com in the logs"},
    )
    assert r.status_code == 201
    f = session.query(Finding).filter_by(organization_id=org.id).one()
    assert "bob@corp.com" not in f.evidence["observation"]
    assert "email" in f.evidence["pii_redacted"]


def test_report_keeps_raw_when_disabled(
    session: Session, org: Organization, client: TestClient
) -> None:
    # Default org has redaction off.
    r = client.post(
        "/findings/report", json={"observation": "email bob@corp.com"}
    )
    assert r.status_code == 201
    f = session.query(Finding).filter_by(organization_id=org.id).one()
    assert "bob@corp.com" in f.evidence["observation"]


# --- erasure ----------------------------------------------------------------
def test_scrub_subject_nested() -> None:
    obj = {"a": "hello bob@corp.com", "b": ["x", "bob@corp.com"]}
    scrubbed, count = scrub_subject(obj, "bob@corp.com")
    assert count == 2
    assert "bob@corp.com" not in str(scrubbed)


def _seed(session: Session, org: Organization) -> None:
    session.add(
        Finding(
            organization_id=org.id,
            rule_id="agent-report",
            title="observation about bob@corp.com",
            severity="high",
            category="data_exfil",
            dedup_key="k1",
            count=1,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            evidence={"observation": "bob@corp.com did something"},
        )
    )
    session.add(
        ApprovalRequest(
            organization_id=org.id,
            agent_id="a1",
            session_id="s1",
            tool_name="email.send",
            tool_arguments={"to": "bob@corp.com"},
            reason="send to bob@corp.com",
            status=ApprovalStatus.PENDING,
        )
    )
    session.commit()


def test_erase_dry_run_previews_without_mutating(
    session: Session, org: Organization
) -> None:
    _seed(session, org)
    result = erase_subject(session, org.id, "bob@corp.com", dry_run=True)
    assert result["findings_scrubbed"] == 1
    assert result["approvals_scrubbed"] == 1
    assert result["occurrences"] >= 3
    # Nothing changed.
    f = session.query(Finding).filter_by(organization_id=org.id).one()
    assert "bob@corp.com" in f.title


def test_erase_scrubs_mutable_stores(session: Session, org: Organization) -> None:
    _seed(session, org)
    result = erase_subject(session, org.id, "bob@corp.com", dry_run=False)
    session.commit()
    assert result["findings_scrubbed"] == 1
    f = session.query(Finding).filter_by(organization_id=org.id).one()
    assert "bob@corp.com" not in f.title
    assert "bob@corp.com" not in str(f.evidence)
    a = session.query(ApprovalRequest).filter_by(organization_id=org.id).one()
    assert "bob@corp.com" not in str(a.tool_arguments)
    assert "bob@corp.com" not in a.reason


def test_erase_endpoint_requires_admin(
    monkeypatch, app, org: Organization
) -> None:
    from app.settings import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["an"])
    monkeypatch.setattr(s, "api_key_orgs", {"an": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"an": "analyst"})
    c = TestClient(app)
    c.headers.update({"X-API-Key": "an", "X-Org-Slug": "acme"})
    assert (
        c.post("/privacy/erase", json={"subject": "bob@corp.com"}).status_code
        == 403
    )
