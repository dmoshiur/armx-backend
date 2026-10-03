# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from functools import lru_cache
from secrets import token_urlsafe
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, PrivateAttr, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.db.urls import (
    DatabaseBackend,
    database_backend,
    libsql_requests_plaintext,
    libsql_requests_tls,
    libsql_target_is_remote,
    normalize_database_url,
)


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

    database_url: str = Field(default="sqlite+libsql:///./armx.db", repr=False)
    database_echo: bool = False
    database_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    # A pre-ping costs one extra round trip per checkout on a remote database; disable only
    # if latency matters more than detecting a half-open connection.
    database_pool_pre_ping: bool = True
    turso_auth_token: SecretStr | None = Field(default=None, repr=False)
    public_api_base_url: str | None = None
    # Comma-separated browser origins for Flutter web/desktop builds. Native mobile clients
    # are unaffected by CORS; leave empty to keep all browser origins blocked.
    cors_allowed_origins: str = ""
    # Render's internal liveness probe reaches the container over plain HTTP with no
    # forwarding header, while public HTTP is redirected to HTTPS at the platform edge.
    # When true, only a parameterless GET /health is answered without TLS; every other
    # request still requires HTTPS outside the demo profile. Enable it on the platform
    # service, never on an instance that is reachable from an untrusted network directly.
    allow_plain_http_health_probe: bool = False

    jwt_secret_key: SecretStr = Field(default=SecretStr(""), repr=False)
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
    mqtt_keepalive_seconds: int = Field(default=30, ge=5, le=600)

    llm_provider: Literal["ashna", "ollama", "openai_compatible", "groq"] = "groq"
    # Ashna AI hosted model (OpenAI-compatible API; docs: https://www.ashna.ai/api-docs).
    # The key comes only from ASHNA_API_KEY and is never logged (AGENTS.md rule 9).
    ashna_api_key: SecretStr | None = Field(default=None, repr=False)
    ashna_base_url: str = "https://api.ashna.ai/v1/api"
    ashna_model: str = "ashna-x1"
    ollama_base_url: str = "https://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    openai_compatible_base_url: str | None = None
    openai_compatible_api_key: SecretStr | None = Field(default=None, repr=False)
    openai_compatible_model: str | None = None
    groq_api_key: SecretStr | None = Field(default=None, repr=False)
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "qwen/qwen3.8-27b"
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
    # Optional convenience setting for demos where an operator cannot run the CLI on the
    # host to approve the initial device; the client must STILL prove possession of the
    # Ed25519 private key via the signed pairing challenge before receiving device_key.
    pairing_auto_approve: bool = False

    @property
    def jwt_secret_was_generated(self) -> bool:
        return self._jwt_secret_generated

    @property
    def cors_origin_list(self) -> list[str]:
        """Explicit browser origins parsed from the comma-separated setting."""

        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

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

        explicit_demo = self.demo_insecure and self.environment in {"local", "demo"}
        self.database_url = normalize_database_url(self.database_url)
        backend = database_backend(self.database_url)
        if backend is DatabaseBackend.UNSUPPORTED:
            raise ValueError(
                "DATABASE_URL must use sqlite+libsql (Turso) or sqlite+aiosqlite "
                "(local development only)"
            )
        if self.environment in {"staging", "production"} and (
            backend is DatabaseBackend.AIOSQLITE
            or (
                backend is DatabaseBackend.LIBSQL and not libsql_target_is_remote(self.database_url)
            )
        ):
            raise ValueError(
                "staging/production require a remote Turso/libSQL database: the platform "
                "filesystem is ephemeral, so a local SQLite file loses data on redeploy"
            )
        if backend is DatabaseBackend.LIBSQL and libsql_target_is_remote(self.database_url):
            token = (
                self.turso_auth_token.get_secret_value().strip()
                if self.turso_auth_token is not None
                else ""
            )
            if not token:
                raise ValueError("TURSO_AUTH_TOKEN is required for a remote libSQL/Turso database")
            if libsql_requests_plaintext(self.database_url) and not explicit_demo:
                raise ValueError(
                    "remote libSQL DATABASE_URL must use TLS (secure=true) outside demo mode"
                )
            if self.environment in {"staging", "production"} and not libsql_requests_tls(
                self.database_url
            ):
                raise ValueError(
                    "staging/production remote libSQL DATABASE_URL must set secure=true"
                )

        origins = self.cors_origin_list
        if origins:
            if "*" in origins:
                raise ValueError(
                    "CORS_ALLOWED_ORIGINS must list explicit origins; wildcards are not allowed"
                )
            secure_profile = self.environment in {"staging", "production"}
            for origin in origins:
                parsed_origin = urlsplit(origin)
                if (
                    not parsed_origin.hostname
                    or parsed_origin.username
                    or parsed_origin.password
                    or parsed_origin.query
                    or parsed_origin.fragment
                    or parsed_origin.path not in {"", "/"}
                    or parsed_origin.scheme not in {"http", "https"}
                    or (secure_profile and parsed_origin.scheme != "https")
                ):
                    raise ValueError(
                        "CORS_ALLOWED_ORIGINS entries must be absolute origins "
                        "(no path, query, or wildcard)"
                    )
        if self.llm_provider == "ashna":
            # Fail startup loudly instead of silently falling back to another provider.
            if self.ashna_api_key is None or not self.ashna_api_key.get_secret_value().strip():
                raise ValueError(
                    "ASHNA_API_KEY is required when LLM_PROVIDER=ashna; create a key at "
                    "https://app.ashna.ai/account?tab=api. For local/offline development "
                    "set LLM_PROVIDER=ollama or LLM_PROVIDER=openai_compatible instead."
                )
            if not self.ashna_model.strip():
                raise ValueError("ASHNA_MODEL must not be empty when LLM_PROVIDER=ashna")
            if not _safe_http_endpoint(self.ashna_base_url, require_tls=not explicit_demo):
                raise ValueError("ASHNA_BASE_URL must be a safe HTTPS endpoint outside demo mode")
        if self.llm_provider == "groq":
            if self.groq_api_key is None or not self.groq_api_key.get_secret_value().strip():
                raise ValueError("GROQ_API_KEY is required when LLM_PROVIDER=groq")
            if not self.groq_model.strip():
                raise ValueError("GROQ_MODEL must not be empty when LLM_PROVIDER=groq")
            if not _safe_http_endpoint(self.groq_base_url, require_tls=True):
                raise ValueError("GROQ_BASE_URL must be a safe HTTPS endpoint")
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
