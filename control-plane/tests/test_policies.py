from __future__ import annotations

from fastapi.testclient import TestClient

_GOOD_YAML = (
    "policies:\n"
    "  - id: allow-http\n"
    "    effect: allow\n"
    "    when: {op: eq, path: tool.name, value: http.get}\n"
    "    reason: ok\n"
)


def test_health_endpoint(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_create_and_list_project(client: TestClient) -> None:
    r = client.post("/projects", json={"name": "demo", "slug": "demo"})
    assert r.status_code == 201
    pid = r.json()["id"]
    assert client.get("/projects").json()[0]["id"] == pid


def test_project_slug_must_be_lowercase_dashed(client: TestClient) -> None:
    r = client.post("/projects", json={"name": "x", "slug": "Demo Project"})
    assert r.status_code == 422


def test_bundle_and_version_lifecycle(client: TestClient) -> None:
    pid = client.post(
        "/projects", json={"name": "demo", "slug": "demo"}
    ).json()["id"]
    bid = client.post(
        f"/projects/{pid}/bundles",
        json={"name": "prod", "description": "production bundle"},
    ).json()["id"]

    # Create v1
    v1 = client.post(
        f"/bundles/{bid}/versions",
        json={"yaml_text": _GOOD_YAML, "author_email": "alice@example.com"},
    )
    assert v1.status_code == 201
    assert v1.json()["version_number"] == 1
    assert v1.json()["policy_count"] == 1

    # Create v2
    v2 = client.post(
        f"/bundles/{bid}/versions",
        json={"yaml_text": _GOOD_YAML},
    )
    assert v2.json()["version_number"] == 2

    versions = client.get(f"/bundles/{bid}/versions").json()
    assert [v["version_number"] for v in versions] == [1, 2]
    # The summary list omits yaml_text; the /full variant includes it in one
    # call (no per-version N+1).
    assert "yaml_text" not in versions[0]
    full = client.get(f"/bundles/{bid}/versions/full").json()
    assert [v["version_number"] for v in full] == [1, 2]
    assert all(v["yaml_text"] == _GOOD_YAML for v in full)


def test_invalid_yaml_rejected_with_422(client: TestClient) -> None:
    pid = client.post(
        "/projects", json={"name": "x", "slug": "x"}
    ).json()["id"]
    bid = client.post(
        f"/projects/{pid}/bundles", json={"name": "b"}
    ).json()["id"]
    r = client.post(
        f"/bundles/{bid}/versions",
        json={"yaml_text": "policies: 1\n"},
    )
    assert r.status_code == 422
    assert "invalid policy bundle" in r.json()["detail"]


def test_rollout_creation_and_active_must_be_full(client: TestClient) -> None:
    pid = client.post(
        "/projects", json={"name": "x", "slug": "x"}
    ).json()["id"]
    bid = client.post(
        f"/projects/{pid}/bundles", json={"name": "b"}
    ).json()["id"]
    vid = client.post(
        f"/bundles/{bid}/versions", json={"yaml_text": _GOOD_YAML}
    ).json()["id"]

    # Staged rollout at 25% is fine.
    r = client.post(
        f"/bundles/{bid}/rollouts",
        json={"version_id": vid, "state": "staged", "rollout_percentage": 25},
    )
    assert r.status_code == 201
    assert r.json()["rollout_percentage"] == 25

    # Active rollout must be 100%.
    r = client.post(
        f"/bundles/{bid}/rollouts",
        json={"version_id": vid, "state": "active", "rollout_percentage": 50},
    )
    assert r.status_code == 422


def test_bundle_under_other_org_not_visible(
    client: TestClient, session, app
) -> None:
    from app.models import Organization

    other = Organization(name="Other", slug="other")
    session.add(other)
    session.commit()

    pid = client.post(
        "/projects", json={"name": "x", "slug": "x"}
    ).json()["id"]
    bid = client.post(
        f"/projects/{pid}/bundles", json={"name": "b"}
    ).json()["id"]

    # Switch to the other org -> bundle should not be reachable.
    from fastapi.testclient import TestClient as Tc

    c2 = Tc(app)
    c2.headers.update({"X-Org-Slug": "other"})
    r = c2.get(f"/bundles/{bid}/versions")
    assert r.status_code == 404
