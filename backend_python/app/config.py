# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from functools import lru_cache
from secrets import token_urlsafe
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from pydantic import Field, PrivateAttr, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _safe_http_endpoint(value: str, *, require_tls: bool) -> bool:
    parsed = urlsplit(value)
    return bool(
        parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and parsed.scheme in ({"https"} if require_tls else {"http", "https"})
    )


class Settings(BaseSettings):
    """Environment-backed configuration; secret fields are redacted from reprs."""

    _jwt_secret_generated: bool = PrivateAttr(default=False)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "A.R.M.X AI Backend"
    environment: Literal["local", "demo", "staging", "production"] = "local"
    demo_insecure: bool = False

    database_url: str = Field(default="sqlite+aiosqlite:///./armx.db", repr=False)
    database_echo: bool = False
    public_api_base_url: str | None = None

    jwt_secret_key: SecretStr = Field(default=SecretStr(""), repr=False)
    bootstrap_admin_username: str = "mohiur"
    bootstrap_admin_password: SecretStr | None = Field(default=None, repr=False)
    bootstrap_admin_email: str = "owner@thamjj13.top"
    bootstrap_admin_display_name: str = "Md. Moshiur Rahman Mohi"
    access_token_ttl_seconds: int = Field(default=1_800, ge=60, le=86_400)
    refresh_token_ttl_seconds: int = Field(default=2_592_000, ge=60, le=31_536_000)
    owner_assertion_ttl_seconds: int = Field(default=60, ge=1, le=60)
    unlock_token_ttl_seconds: int = Field(default=30, ge=1, le=30)
    auth_max_failures: int = Field(default=5, ge=1, le=20)
    auth_lockout_seconds: int = Field(default=900, ge=30, le=86_400)

    mqtt_enabled: bool = False
    mqtt_host: str = "localhost"
    mqtt_port: int = Field(default=8883, ge=1, le=65_535)
    mqtt_username: str | None = None
    mqtt_password: SecretStr | None = Field(default=None, repr=False)
    mqtt_tls_ca_file: str | None = None
    mqtt_client_id: str = "armx-backend"

    llm_provider: Literal["ollama", "openai_compatible"] = "ollama"
    ollama_base_url: str = "https://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    openai_compatible_base_url: str | None = None
    openai_compatible_api_key: SecretStr | None = Field(default=None, repr=False)
    openai_compatible_model: str | None = None
    llm_timeout_seconds: float = Field(default=60.0, gt=0, le=300)

    github_token: SecretStr | None = Field(default=None, repr=False)
    github_repository: str | None = None
    mail_imap_host: str | None = None
    mail_imap_username: str | None = None
    mail_imap_password: SecretStr | None = Field(default=None, repr=False)
    mail_smtp_host: str | None = None
    mail_smtp_username: str | None = None
    mail_smtp_password: SecretStr | None = Field(default=None, repr=False)
    mail_enabled: bool = False
    github_enabled: bool = False
    notes_enabled: bool = True
    mqtt_tool_enabled: bool = False
    intercom_enabled: bool = True

    @property
    def jwt_secret_was_generated(self) -> bool:
        return self._jwt_secret_generated

    @model_validator(mode="after")
    def validate_deployment_profile(self) -> "Settings":
        if self.environment in {"staging", "production"} and self.demo_insecure:
            raise ValueError("DEMO_INSECURE must be false outside local/demo profiles")

        signing_key = self.jwt_secret_key.get_secret_value()
        if len(signing_key) < 32:
            if self.environment in {"local", "demo"}:
                # This ephemeral fallback avoids a hard-coded demo secret. Supply
                # JWT_SECRET_KEY in .env when sessions must survive process restarts.
                self.jwt_secret_key = SecretStr(token_urlsafe(48))
                self._jwt_secret_generated = True
            else:
                raise ValueError(
                    "JWT_SECRET_KEY must contain at least 32 characters in deployed profiles"
                )

        if self.environment in {"staging", "production"}:
            if not self.database_url.startswith("postgresql+asyncpg://"):
                raise ValueError("staging/production profiles require PostgreSQL")
        elif not (
            self.database_url.startswith("sqlite+aiosqlite://")
            or self.database_url.startswith("postgresql+asyncpg://")
        ):
            raise ValueError("DATABASE_URL must use sqlite+aiosqlite or postgresql+asyncpg")

        explicit_demo = self.demo_insecure and self.environment in {"local", "demo"}
        if self.database_url.startswith("postgresql+asyncpg://") and not explicit_demo:
            ssl_mode = parse_qs(urlsplit(self.database_url).query).get("ssl", [""])[-1]
            if ssl_mode not in {"require", "verify-ca", "verify-full"}:
                raise ValueError("PostgreSQL DATABASE_URL must set ssl=require or stronger")
        if self.llm_provider == "ollama" and not _safe_http_endpoint(
            self.ollama_base_url, require_tls=not explicit_demo
        ):
            raise ValueError("OLLAMA_BASE_URL must be a safe HTTPS endpoint outside demo mode")

        if self.environment in {"staging", "production"} and not self.public_api_base_url:
            raise ValueError("PUBLIC_API_BASE_URL is required for deployed profiles")
        if (
            self.environment in {"staging", "production"}
            and self.mqtt_enabled
            and (
                not self.mqtt_username
                or not self.mqtt_username.strip()
                or self.mqtt_password is None
                or not self.mqtt_password.get_secret_value()
            )
        ):
            raise ValueError("MQTT_USERNAME and MQTT_PASSWORD are required for deployed profiles")
        if self.bootstrap_admin_password is not None:
            if len(self.bootstrap_admin_password.get_secret_value()) < 12:
                raise ValueError("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters")
            if not self.bootstrap_admin_username.strip() or len(self.bootstrap_admin_username) > 64:
                raise ValueError("BOOTSTRAP_ADMIN_USERNAME must be 1–64 characters")
            if len(self.bootstrap_admin_email) > 254:
                raise ValueError("BOOTSTRAP_ADMIN_EMAIL must be at most 254 characters")
        if self.public_api_base_url:
            parsed_base = urlsplit(self.public_api_base_url)
            secure_profile = not (self.demo_insecure and self.environment in {"local", "demo"})
            if (
                not parsed_base.hostname
                or parsed_base.username
                or parsed_base.password
                or parsed_base.query
                or parsed_base.fragment
                or (secure_profile and parsed_base.scheme != "https")
                or (not secure_profile and parsed_base.scheme not in {"http", "https"})
            ):
                raise ValueError("PUBLIC_API_BASE_URL must be an absolute safe API origin")

        if self.llm_provider == "openai_compatible":
            if not self.openai_compatible_base_url or not self.openai_compatible_model:
                raise ValueError(
                    "OPENAI_COMPATIBLE_BASE_URL and OPENAI_COMPATIBLE_MODEL "
                    "are required for that LLM provider"
                )
            if not _safe_http_endpoint(
                self.openai_compatible_base_url, require_tls=not explicit_demo
            ):
                raise ValueError("OpenAI-compatible provider URL must be a safe HTTPS endpoint")

        if self.github_repository and (
            len(self.github_repository) > 200
            or len(self.github_repository.split("/")) != 2
            or not all(
                part and part.replace("-", "").replace("_", "").isalnum()
                for part in self.github_repository.split("/")
            )
        ):
            raise ValueError("GITHUB_REPOSITORY must use the owner/repository format")

        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance."""

    return Settings()
