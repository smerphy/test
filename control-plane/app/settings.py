"""12-factor configuration via pydantic-settings.

All settings are sourced from environment variables prefixed with
`PRAETOR_`. A `.env` file in the working directory is loaded if present.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Placeholder session secret. create_app() refuses to boot with this value
# outside dev mode, since it signs browser auth cookies.
DEFAULT_SESSION_SECRET = "dev-only-replace-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PRAETOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Explicit development mode. Must be set to true to run without configured
    # API keys or with the placeholder secrets below; otherwise the app
    # fail-closes (401 on the API-key path, refuses to boot with a default
    # signing secret). NEVER enable in production.
    dev_mode: bool = Field(default=False)

    # Defaults to in-memory SQLite for tests. Production: postgresql+psycopg://...
    database_url: str = Field(default="sqlite+pysqlite:///:memory:")

    # MVP auth: caller passes one of these keys in `X-API-Key`.
    # Set via `PRAETOR_API_KEYS=key1,key2` (comma-separated).
    api_keys: list[str] = Field(default_factory=list)

    # Per-key organization binding: maps an API key to the slug of the
    # single organization it is authorized for. Set via
    # `PRAETOR_API_KEY_ORGS='{"key1": "acme"}'`. When a key is bound here,
    # it can only ever resolve to that organization — a mismatched
    # `X-Org-Slug` header is rejected rather than honored. This is what
    # closes cross-tenant access for API-key traffic; keys left unbound are
    # only usable in single-organization deployments.
    api_key_orgs: dict[str, str] = Field(default_factory=dict)

    # Per-key RBAC role. Maps an API key to one of viewer/analyst/admin/owner,
    # set via `PRAETOR_API_KEY_ROLES='{"ingest-key": "analyst"}'`. Keys not
    # listed fall back to `api_key_default_role`. This lets you mint read-only
    # keys (SIEM pulls, dashboards) and least-privilege sensor keys while
    # reserving config changes for admin keys.
    api_key_roles: dict[str, str] = Field(default_factory=dict)
    # Role granted to a valid API key that is not named in `api_key_roles`.
    # Defaults to `admin` so existing keys keep full API access after RBAC
    # lands (non-breaking); tighten to `analyst` or `viewer` to opt into
    # least privilege by default.
    api_key_default_role: str = Field(default="admin")

    # SCIM 2.0 provisioning: bearer token → org slug. An IdP (Okta/Azure AD)
    # calls /scim/v2/Users with `Authorization: Bearer <token>`. Set via
    # `PRAETOR_SCIM_TOKENS='{"tok": "acme"}'`. Unset = SCIM disabled (401).
    scim_tokens: dict[str, str] = Field(default_factory=dict)

    structured_logs: bool = Field(default=True)

    # --- Secrets at rest -------------------------------------------------
    # Fernet keys (comma-separated) for envelope-encrypting tenant secrets
    # (BYO AI keys, feed auth headers). The first key encrypts; all keys are
    # tried on decrypt (rotate by prepending a new one). Unset = secrets are
    # stored as plaintext (dev only — set this in any real deployment).
    # Generate: python -c "from cryptography.fernet import Fernet;
    # print(Fernet.generate_key().decode())"
    secret_keys: list[str] = Field(default_factory=list)

    # --- Rate limiting (per-tenant token buckets) -----------------------
    rate_limit_enabled: bool = Field(default=True)
    # Requests/minute per org, by bucket. Cheap ingest is generous; expensive
    # AI calls are tight. Capacity = one minute's worth (burst), refilled
    # steadily.
    rate_limit_ingest_per_min: int = Field(default=6000)
    rate_limit_ai_per_min: int = Field(default=60)
    rate_limit_default_per_min: int = Field(default=1200)

    # --- AI-native advisory ---------------------------------------------
    # Deployment-level guardrails for the opt-in AI service. Orgs bring their
    # own key/model; these bound what the platform permits.
    # Allow an org to point ai_base_url at a private/non-global address (for a
    # self-hosted model like a local Ollama). Off by default: base URLs are
    # egress-guarded like any other outbound target (SSRF protection).
    ai_allow_private_endpoints: bool = Field(default=False)
    # Cap on tokens per agent call (bounds cost + latency).
    ai_max_tokens: int = Field(default=1024)
    ai_request_timeout_seconds: float = Field(default=30.0)
    # Estimated BYOK price per million tokens (used only for budget guardrails;
    # a rough proxy across vendors/models). Override per deployment.
    ai_price_input_per_mtok: float = Field(default=3.0)
    ai_price_output_per_mtok: float = Field(default=15.0)

    # --- Scale-out event store ------------------------------------------
    # Cold tier: append-only NDJSON archive root for full-fidelity telemetry.
    # In production point this at an object-store mount (s3fs / gcsfuse) so
    # raw events are retained cheaply and indefinitely off the hot database.
    # Empty = archival disabled (a no-op sink).
    event_archive_dir: str = Field(default="")
    # Whether the ingest path also gzips archived partitions.
    event_archive_gzip: bool = Field(default=True)
    # Hot-store retention: raw audit events older than this many days are
    # rolled into queryable daily aggregates and pruned from the hot table,
    # bounding the primary store under high volume. None = keep raw forever.
    audit_retention_days: int | None = Field(default=None)
    # Classification-aware retention: per-classification override windows (days)
    # keyed by the event's data classification, e.g.
    # `PRAETOR_AUDIT_RETENTION_DAYS_BY_CLASS='{"restricted": 30}'` purges
    # PII-bearing ("restricted") events after 30 days regardless of the default
    # window above. Classifications not listed fall back to `audit_retention_days`.
    audit_retention_days_by_class: dict[str, int] = Field(default_factory=dict)
    # Max raw rows a single retention pass rolls up + prunes (bounds the
    # transaction; the scheduled task re-runs until caught up).
    retention_batch_size: int = Field(default=50_000)

    # --- PII: telemetry classification + field encryption ----------------
    # Classify each audit event at ingest by scanning its payload for PII
    # (emails/SSNs/cards/secrets/…): "restricted" if any is present, else
    # "standard". Drives classification-aware retention. Off by default (adds a
    # cheap regex scan to the ingest hot path).
    classify_telemetry: bool = Field(default=False)
    # Encrypt the richest sensitive audit payload fields (tool_arguments,
    # context, suggested_transform) at rest with the same Fernet keys as
    # `secret_keys`. A DB dump then leaks ciphertext, not raw tool arguments.
    # Requires `secret_keys` to be set; off by default.
    telemetry_field_encryption: bool = Field(default=False)

    # Celery broker + result backend. Default to in-process eager so tests
    # and `uvicorn` runs don't require Redis. Production: redis://...
    celery_broker_url: str = Field(default="memory://")
    celery_result_backend: str = Field(default="cache+memory://")
    celery_task_always_eager: bool = Field(default=True)

    # How long a pending approval lives before the sweep marks it EXPIRED.
    approval_ttl_minutes: int = Field(default=60)

    # Slack app signing secret for verifying interactive-component callbacks
    # (the Approve/Deny buttons POST to /approvals/slack/actions). Unset =
    # the endpoint 503s. See https://api.slack.com/authentication/verifying-requests-from-slack
    slack_signing_secret: str = Field(default="")

    # OAuth (GitHub). When client_id is unset, /auth/* endpoints 503.
    github_client_id: str = Field(default="")
    github_client_secret: str = Field(default="")
    # Generic OIDC SSO (Okta, Azure AD, Auth0, Keycloak, …). When issuer +
    # client_id are unset, /auth/oidc/* endpoints 503.
    oidc_issuer: str = Field(default="")
    oidc_client_id: str = Field(default="")
    oidc_client_secret: str = Field(default="")
    oauth_redirect_base_url: str = Field(default="http://localhost:8000")
    session_secret: str = Field(default=DEFAULT_SESSION_SECRET)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


__all__ = ["Settings", "get_settings"]
