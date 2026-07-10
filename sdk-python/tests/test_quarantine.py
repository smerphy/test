from __future__ import annotations

import httpx
from ephorate_engine.evaluator import Policy
from ephorate_engine.predicates import AlwaysPredicate
from ephorate_engine.types import Decision

from ephorate.client import EphorateClient
from ephorate.quarantine import QuarantineGuard


def _guard(
    isolated: list[dict], *, fail_closed: bool = False
) -> QuarantineGuard:
    """Build a guard whose control plane isolates any (agent_id, session_id)
    listed in ``isolated`` (matching the authoritative /quarantines/check
    semantics: kill-switch + spend + per-entity quarantine composed server-side)."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/quarantines/check"
        agent = request.url.params.get("agent_id")
        session = request.url.params.get("session_id")
        for rule in isolated:
            if (rule.get("agent_id") and rule["agent_id"] == agent) or (
                rule.get("session_id") and rule["session_id"] == session
            ):
                return httpx.Response(
                    200, json={"quarantined": True, "reason": rule["reason"]}
                )
        return httpx.Response(200, json={"quarantined": False, "reason": None})

    return QuarantineGuard(
        "http://cp",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        fail_closed=fail_closed,
    )


def test_guard_flags_quarantined_agent() -> None:
    g = _guard([{"agent_id": "rogue", "session_id": None, "reason": "bad"}])
    assert g.check("rogue", "s1") == "bad"
    assert g.check("good", "s1") is None


def test_guard_flags_quarantined_session() -> None:
    g = _guard([{"agent_id": None, "session_id": "s-x", "reason": "probing"}])
    assert g.check("a", "s-x") == "probing"
    assert g.check("a", "s-y") is None


def test_guard_reflects_global_kill_switch() -> None:
    # The control plane composes the kill-switch into /quarantines/check, so a
    # halted org denies *any* agent — even one with no per-entity quarantine.
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/quarantines/check"
        return httpx.Response(
            200,
            json={"quarantined": True, "reason": "organization halted (kill-switch)"},
        )

    g = QuarantineGuard(
        "http://cp",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert g.check("any-agent", "any-session") == "organization halted (kill-switch)"


def test_guard_fail_open_when_unreachable() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    g = QuarantineGuard(
        "http://cp", http_client=httpx.Client(transport=httpx.MockTransport(boom))
    )
    assert g.check("a", "s") is None  # fail open (availability)


def test_guard_fail_closed_when_unreachable() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    g = QuarantineGuard(
        "http://cp",
        http_client=httpx.Client(transport=httpx.MockTransport(boom)),
        fail_closed=True,
    )
    assert g.check("a", "s") is not None


def test_guard_reuses_cached_verdict_when_refresh_fails() -> None:
    # Availability: once a verdict is cached, a later transient failure reuses
    # it rather than flipping to fail-open.
    clock = [0.0]
    calls = [0]

    def handler(request: httpx.Request) -> httpx.Response:
        calls[0] += 1
        if calls[0] == 1:
            return httpx.Response(200, json={"quarantined": True, "reason": "bad"})
        raise httpx.ConnectError("down")

    g = QuarantineGuard(
        "http://cp",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        ttl_seconds=30.0,
        monotonic=lambda: clock[0],
    )
    assert g.check("rogue", "s1") == "bad"  # first fetch caches
    clock[0] = 100.0  # cache now stale -> refresh, which fails
    assert g.check("rogue", "s1") == "bad"  # reuses last-known verdict


def test_guard_close_is_safe() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"quarantined": False})

    g = QuarantineGuard(
        "http://cp",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    g.close()  # injected client: not owned, no error


def test_client_denies_quarantined_agent_before_policy() -> None:
    # An allow-all policy would normally allow; quarantine must win.
    allow_all = Policy(
        id="allow-all", effect=Decision.ALLOW, when=AlwaysPredicate(), reason="ok"
    )
    client = EphorateClient(policies=[allow_all], default_agent_id="rogue")
    # Inject a guard directly (no control plane wiring needed for the test).
    client._quarantine = _guard(
        [{"agent_id": "rogue", "session_id": None, "reason": "isolated"}]
    )
    result = client.evaluate("http.get", {"url": "https://x"}, session_id="s1")
    assert result.decision is Decision.DENY
    assert "quarantined" in result.reason
    assert result.matched_policy_id == "__quarantine__"


def test_client_allows_non_quarantined_agent() -> None:
    allow_all = Policy(
        id="allow-all", effect=Decision.ALLOW, when=AlwaysPredicate(), reason="ok"
    )
    client = EphorateClient(policies=[allow_all], default_agent_id="clean")
    client._quarantine = _guard(
        [{"agent_id": "rogue", "session_id": None, "reason": "isolated"}]
    )
    result = client.evaluate("http.get", {"url": "https://x"}, session_id="s1")
    assert result.decision is Decision.ALLOW
