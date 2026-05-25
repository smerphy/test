"""12-factor configuration via pydantic-settings.

All settings are sourced from environment variables prefixed with
`PRAETOR_`. A `.env` file in the working directory is loaded if present.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PRAETOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Defaults to in-memory SQLite for tests. Production: postgresql+psycopg://...
    database_url: str = Field(default="sqlite+pysqlite:///:memory:")

    # MVP auth: caller passes one of these keys in `X-API-Key`.
    # Set via `PRAETOR_API_KEYS=key1,key2` (comma-separated).
    api_keys: list[str] = Field(default_factory=list)

    # Approval webhook callbacks land here; we re-emit to subscribed
    # SDKs via the registry pattern. URL is provided per-org once
    # multi-tenancy is wired in.
    approval_callback_secret: str = Field(default="dev-only-not-secret")

    structured_logs: bool = Field(default=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


__all__ = ["Settings", "get_settings"]
