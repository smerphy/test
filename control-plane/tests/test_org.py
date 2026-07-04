from __future__ import annotations

from fastapi.testclient import TestClient


def test_get_org_returns_current_org(client: TestClient) -> None:
    r = client.get("/org")
    assert r.status_code == 200
    body = r.json()
    assert body["slug"] == "acme"
    assert body["approval_webhook_url"] is None


def test_patch_org_sets_approval_webhook(client: TestClient) -> None:
    r = client.patch(
        "/org", json={"approval_webhook_url": "https://example.com/hook"}
    )
    assert r.status_code == 200
    assert r.json()["approval_webhook_url"] == "https://example.com/hook"
    # Persisted for subsequent reads.
    assert (
        client.get("/org").json()["approval_webhook_url"]
        == "https://example.com/hook"
    )


def test_patch_org_rejects_internal_webhook(client: TestClient) -> None:
    # SSRF guard: an internal/metadata URL must be rejected at write time.
    r = client.patch(
        "/org", json={"approval_webhook_url": "http://169.254.169.254/latest/"}
    )
    assert r.status_code == 422


def test_patch_org_can_clear_webhook(client: TestClient) -> None:
    client.patch("/org", json={"approval_webhook_url": "https://example.com/hook"})
    r = client.patch("/org", json={"approval_webhook_url": None})
    assert r.json()["approval_webhook_url"] is None


def test_create_approval_dispatches_notification(
    client: TestClient, monkeypatch
) -> None:
    # Prove the create endpoint fires the notification task (eager mode runs
    # it inline) without making a real outbound request.
    calls: list[str] = []
    monkeypatch.setattr(
        "app.workers.tasks.deliver_approval_notification",
        lambda session, approval_id: calls.append(approval_id) or True,
    )
    r = client.post(
        "/approvals",
        json={
            "agent_id": "a",
            "session_id": "s",
            "tool_name": "http.post",
            "tool_arguments": {},
            "policy_id": "p",
            "reason": "r",
        },
    )
    assert r.status_code == 201
    assert calls == [r.json()["id"]]
