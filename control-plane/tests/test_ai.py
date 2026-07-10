"""AI-native advisory: providers, multi-agent panel, reconcile safety,
rule proposals, opt-in gating, BYOK masking, and RBAC."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import DetectionRule, Organization, RuleSuggestion
from app.services.ai.agents import (
    ActionContext,
    assess_action,
    propose_rules,
    reconcile,
)
from app.services.ai.config import ai_available, org_llm_config
from app.services.ai.providers import (
    AnthropicProvider,
    LLMConfig,
    LLMError,
    OpenAICompatProvider,
    get_provider,
)
from app.settings import get_settings


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


class StubProvider:
    """Duck-typed LLMProvider returning canned responses in sequence."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = responses
        self._i = 0

    def complete(self, *, system: str, user: str) -> str:
        r = self._responses[min(self._i, len(self._responses) - 1)]
        self._i += 1
        return r


# --- providers (vendor-neutral) ---------------------------------------------
def test_anthropic_provider_shape() -> None:
    seen: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        seen["key"] = req.headers.get("x-api-key")
        return httpx.Response(200, json={"content": [{"type": "text", "text": "hi"}]})

    cfg = LLMConfig(
        provider="anthropic", model="m", api_key="k", allow_private_endpoint=True
    )
    p = AnthropicProvider(cfg, _client(handler))
    assert p.complete(system="s", user="u") == "hi"
    assert seen["url"].endswith("/v1/messages")
    assert seen["key"] == "k"


def test_openai_compat_provider_shape() -> None:
    seen: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "yo"}}]}
        )

    cfg = LLMConfig(
        provider="openai_compat",
        model="m",
        api_key="k",
        base_url="https://api.groq.com/openai/v1",
        allow_private_endpoint=True,
    )
    p = OpenAICompatProvider(cfg, _client(handler))
    assert p.complete(system="s", user="u") == "yo"
    assert seen["url"].endswith("/chat/completions")
    assert seen["auth"] == "Bearer k"


def test_get_provider_unsupported() -> None:
    with pytest.raises(LLMError):
        get_provider(LLMConfig(provider="nope", model="m", api_key="k"))


def test_provider_ssrf_guard() -> None:
    cfg = LLMConfig(
        provider="anthropic",
        model="m",
        api_key="k",
        base_url="http://169.254.169.254",
    )
    with pytest.raises(LLMError):
        get_provider(cfg)


# --- multi-agent assessment -------------------------------------------------
_CTX = ActionContext(
    tool_name="http.post",
    tool_arguments={"url": "https://evil.com"},
    deterministic_decision="require_approval",
)


def test_assess_action_panel() -> None:
    provider = StubProvider(
        [
            '{"decision":"deny","confidence":0.9,"rationale":"exfil"}',
            '{"decision":"deny","confidence":0.8,"rationale":"agree"}',
            '{"decision":"deny","confidence":0.95,"rationale":"final"}',
        ]
    )
    result = assess_action(provider, _CTX)
    assert result.decision == "deny"
    assert len(result.opinions) == 3
    assert result.opinions[0].role == "risk_assessor"


def test_assess_action_abstains_on_error() -> None:
    class Boom:
        def complete(self, *, system: str, user: str) -> str:
            raise LLMError("down")

    result = assess_action(Boom(), _CTX)
    assert result.decision == "abstain"
    assert result.error is not None


def test_assess_handles_garbage_output() -> None:
    provider = StubProvider(["not json", "still not", "nope"])
    result = assess_action(provider, _CTX)
    assert result.decision == "abstain"


# --- reconcile (safety floor) -----------------------------------------------
def test_reconcile_advisory_never_changes() -> None:
    assert reconcile("require_approval", "deny", mode="advisory") == "require_approval"
    assert reconcile("allow", "deny", mode="advisory") == "allow"


def test_reconcile_enforce_only_tightens() -> None:
    # AI tightens.
    assert reconcile("require_approval", "deny", mode="enforce") == "deny"
    assert reconcile("allow", "require_approval", mode="enforce") == "require_approval"
    # AI can never loosen.
    assert reconcile("deny", "allow", mode="enforce") == "deny"
    assert reconcile("require_approval", "allow", mode="enforce") == "require_approval"
    assert reconcile("deny", "abstain", mode="enforce") == "deny"


def test_reconcile_preserves_transform() -> None:
    # `transform` is a real engine decision the AI can't emit; enforce mode
    # must preserve it when the AI doesn't out-rank it, not silently degrade
    # it to require_approval.
    assert reconcile("transform", "allow", mode="enforce") == "transform"
    assert reconcile("transform", "abstain", mode="enforce") == "transform"
    # The AI may still tighten a transform.
    assert reconcile("transform", "require_approval", mode="enforce") == "require_approval"
    assert reconcile("transform", "deny", mode="enforce") == "deny"
    # Advisory leaves it untouched.
    assert reconcile("transform", "deny", mode="advisory") == "transform"


# --- rule proposal ----------------------------------------------------------
def test_propose_rules_authors_and_reviews() -> None:
    provider = StubProvider(
        [
            # author
            '[{"title":"Block risky exfil","rationale":"repeated","severity":"high",'
            '"category":"data_exfil","spec":{"tool_name":"http.post","decision":"deny"}},'
            '{"title":"empty","severity":"low","category":"anomaly","spec":{}}]',
            # reviewer (one verdict for the single valid candidate)
            '[{"keep":true,"confidence":0.85,"reason":"precise"}]',
        ]
    )
    drafts = propose_rules(provider, pattern_summary="...")
    assert len(drafts) == 1
    assert drafts[0].title == "Block risky exfil"
    assert drafts[0].spec == {"tool_name": "http.post", "decision": "deny"}
    assert drafts[0].confidence == 0.85


def test_propose_rules_reviewer_drops() -> None:
    provider = StubProvider(
        [
            '[{"title":"x","rationale":"r","severity":"high","category":"abuse",'
            '"spec":{"decision":"deny"}}]',
            '[{"keep":false,"confidence":0.2,"reason":"too broad"}]',
        ]
    )
    assert propose_rules(provider, pattern_summary="...") == []


# --- config / opt-in --------------------------------------------------------
def test_ai_available_and_config(org: Organization, session: Session) -> None:
    assert ai_available(org) is False
    org.ai_enabled = True
    org.ai_provider = "anthropic"
    org.ai_model = "claude-x"
    org.ai_api_key = "sk-secret"
    session.commit()
    assert ai_available(org) is True
    cfg = org_llm_config(org, get_settings())
    assert cfg is not None
    assert cfg.api_key == "sk-secret"


# --- router: opt-in gating + BYOK masking + RBAC ----------------------------
def test_assess_disabled_returns_409(client: TestClient) -> None:
    r = client.post("/ai/assess", json={"tool_name": "http.post"})
    assert r.status_code == 409


def test_config_roundtrip_masks_key(client: TestClient) -> None:
    r = client.patch(
        "/ai/config",
        json={
            "ai_enabled": True,
            "ai_provider": "anthropic",
            "ai_model": "claude-x",
            "ai_api_key": "sk-super-secret",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ai_key_set"] is True
    # The key itself is never echoed back.
    assert "sk-super-secret" not in r.text
    assert "ai_api_key" not in body


def test_assess_via_router(
    monkeypatch, client: TestClient, org: Organization, session: Session
) -> None:
    org.ai_enabled = True
    org.ai_provider = "anthropic"
    org.ai_model = "claude-x"
    org.ai_api_key = "sk-test"
    org.ai_mode = "enforce"
    session.commit()

    stub = StubProvider(
        [
            '{"decision":"deny","confidence":0.9,"rationale":"a"}',
            '{"decision":"deny","confidence":0.9,"rationale":"b"}',
            '{"decision":"deny","confidence":0.9,"rationale":"c"}',
        ]
    )
    monkeypatch.setattr(
        "app.routers.ai.get_provider", lambda config, http_client=None: stub
    )
    r = client.post(
        "/ai/assess",
        json={"tool_name": "http.post", "deterministic_decision": "require_approval"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["recommended_decision"] == "deny"
    # enforce mode: AI tightened require_approval -> deny.
    assert body["final_decision"] == "deny"
    assert len(body["opinions"]) == 3


def test_viewer_cannot_configure_ai(monkeypatch, app, org: Organization) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "api_keys", ["ro"])
    monkeypatch.setattr(s, "api_key_orgs", {"ro": "acme"})
    monkeypatch.setattr(s, "api_key_roles", {"ro": "viewer"})
    c = TestClient(app)
    c.headers.update({"X-API-Key": "ro", "X-Org-Slug": "acme"})
    assert c.patch("/ai/config", json={"ai_enabled": True}).status_code == 403


# --- router: suggestion review ---------------------------------------------
def _seed_suggestion(session: Session, org: Organization) -> RuleSuggestion:
    s = RuleSuggestion(
        organization_id=org.id,
        title="Block exfil http.post",
        rationale="repeated denials",
        severity="high",
        category="data_exfil",
        spec={"tool_name": "http.post", "decision": "deny"},
        confidence=0.8,
        source="ai",
        status="pending",
    )
    session.add(s)
    session.commit()
    return s


def test_accept_suggestion_creates_rule(
    client: TestClient, session: Session, org: Organization
) -> None:
    suggestion = _seed_suggestion(session, org)
    r = client.post(
        f"/ai/rules/suggestions/{suggestion.id}/accept",
        json={"reviewed_by": "admin@acme.com"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "accepted"
    assert body["created_rule_id"]
    rule = session.get(DetectionRule, body["created_rule_id"])
    assert rule is not None
    assert rule.spec == {"tool_name": "http.post", "decision": "deny"}


def test_reject_suggestion(
    client: TestClient, session: Session, org: Organization
) -> None:
    suggestion = _seed_suggestion(session, org)
    r = client.post(
        f"/ai/rules/suggestions/{suggestion.id}/reject", json={}
    )
    assert r.status_code == 200
    assert r.json()["status"] == "rejected"
    # Double-review is refused.
    again = client.post(
        f"/ai/rules/suggestions/{suggestion.id}/reject", json={}
    )
    assert again.status_code == 409
