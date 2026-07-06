"""Vendor-neutral LLM provider layer.

Two HTTP adapters cover essentially the whole market:

* ``anthropic``      — Claude Messages API (``/v1/messages``).
* ``openai_compat``  — OpenAI Chat Completions (``/v1/chat/completions``),
  which also speaks for Azure OpenAI, Groq, Together, Mistral, Fireworks,
  OpenRouter, Ollama, vLLM, LM Studio, and any other OpenAI-compatible server.

The org brings its own key, model, and (optionally) base URL — the platform
never ships a default vendor. All outbound calls are egress-guarded (SSRF)
unless the deployment explicitly allows private endpoints (for self-hosted
models). Providers take an injectable ``httpx.Client`` so they are testable
without network access.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.services.egress import EgressBlocked, assert_safe_webhook_url

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI_COMPAT = "openai_compat"
SUPPORTED_PROVIDERS = (PROVIDER_ANTHROPIC, PROVIDER_OPENAI_COMPAT)

_DEFAULT_BASE_URL = {
    PROVIDER_ANTHROPIC: "https://api.anthropic.com",
    PROVIDER_OPENAI_COMPAT: "https://api.openai.com/v1",
}


class LLMError(Exception):
    """Any failure talking to the configured provider."""


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    api_key: str
    base_url: str | None = None
    max_tokens: int = 1024
    timeout_seconds: float = 30.0
    allow_private_endpoint: bool = False

    def resolved_base_url(self) -> str:
        return (self.base_url or _DEFAULT_BASE_URL.get(self.provider, "")).rstrip(
            "/"
        )


class LLMProvider:
    """Base class: subclasses implement `complete`."""

    def __init__(
        self, config: LLMConfig, http_client: httpx.Client | None = None
    ) -> None:
        self.config = config
        base = config.resolved_base_url()
        if not base:
            raise LLMError(f"no base URL for provider {config.provider!r}")
        # SSRF guard on the (possibly org-supplied) endpoint unless the
        # deployment opted into private endpoints for self-hosted models.
        if not config.allow_private_endpoint:
            try:
                assert_safe_webhook_url(base)
            except EgressBlocked as exc:
                raise LLMError(f"AI endpoint rejected: {exc}") from exc
        self._client = http_client or httpx.Client(timeout=config.timeout_seconds)

    def complete(self, *, system: str, user: str) -> str:
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    def complete(self, *, system: str, user: str) -> str:
        url = f"{self.config.resolved_base_url()}/v1/messages"
        try:
            resp = self._client.post(
                url,
                headers={
                    "x-api-key": self.config.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.config.model,
                    "max_tokens": self.config.max_tokens,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"anthropic request failed: {exc}") from exc
        try:
            blocks = data["content"]
            return "".join(
                b.get("text", "") for b in blocks if b.get("type") == "text"
            )
        except (KeyError, TypeError) as exc:
            raise LLMError(f"unexpected anthropic response: {exc}") from exc


class OpenAICompatProvider(LLMProvider):
    def complete(self, *, system: str, user: str) -> str:
        url = f"{self.config.resolved_base_url()}/chat/completions"
        try:
            resp = self._client.post(
                url,
                headers={
                    "authorization": f"Bearer {self.config.api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": self.config.model,
                    "max_tokens": self.config.max_tokens,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"openai-compat request failed: {exc}") from exc
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected openai-compat response: {exc}") from exc


def get_provider(
    config: LLMConfig, http_client: httpx.Client | None = None
) -> LLMProvider:
    if config.provider == PROVIDER_ANTHROPIC:
        return AnthropicProvider(config, http_client)
    if config.provider == PROVIDER_OPENAI_COMPAT:
        return OpenAICompatProvider(config, http_client)
    raise LLMError(
        f"unsupported provider {config.provider!r}; "
        f"choose one of {SUPPORTED_PROVIDERS}"
    )


__all__ = [
    "PROVIDER_ANTHROPIC",
    "PROVIDER_OPENAI_COMPAT",
    "SUPPORTED_PROVIDERS",
    "AnthropicProvider",
    "LLMConfig",
    "LLMError",
    "LLMProvider",
    "OpenAICompatProvider",
    "get_provider",
]
