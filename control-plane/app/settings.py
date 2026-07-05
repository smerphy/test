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

    structured_logs: bool = Field(default=True)

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
    oauth_redirect_base_url: str = Field(default="http://localhost:8000")
    session_secret: str = Field(default=DEFAULT_SESSION_SECRET)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


__all__ = ["Settings", "get_settings"]
