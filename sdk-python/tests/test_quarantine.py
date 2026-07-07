from __future__ import annotations

import httpx
from ephorate_engine.evaluator import Policy
from ephorate_engine.predicates import AlwaysPredicate
from ephorate_engine.types import Decision

from ephorate.client import EphorateClient
from ephorate.quarantine import QuarantineGuard


def _guard(active: list[dict], *, fail_closed: bool = False) -> QuarantineGuard:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/quarantines/active"
        return httpx.Response(200, json=active)

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
