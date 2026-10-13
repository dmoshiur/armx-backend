# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Typed, validated settings.

Rules enforced here (see `docs/security.md`):

* No secret ever has a hardcoded default. Every credential is an env var.
* ``ENVIRONMENT=production`` refuses to boot when a required secret is missing or
  still set to a placeholder value.
* Deriving a development-only ephemeral secret logs a warning and is recorded on the
  settings object so ``/health`` and the startup banner can surface it.
"""

from __future__ import annotations

import secrets as _secrets
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.ratelimit_spec import RateLimitSpec, parse_rate_limit
from app.integrations.specs import (
    McpServerSpec,
    N8nWorkflowSpec,
    parse_csv,
    parse_mcp_servers,
    parse_n8n_workflows,
)

Environment = Literal["development", "demo", "staging", "production"]

#: Values that look like a credential but are obviously not one. A production boot
#: treats any of these as "missing" so a copied .env.example can never go live.
_PLACEHOLDER_MARKERS = (
    "changeme",
    "change-me",
    "change_me",
    "placeholder",
    "replace-me",
    "replace_me",
    "your-",
    "your_",
    "example.com",
    "xxxxxxxx",
)


def _is_missing(value: str | SecretStr | None) -> bool:
    """True when a credential is unset, blank, or an obvious placeholder."""
    if value is None:
        return True
    text = value.get_secret_value() if isinstance(value, SecretStr) else value
    text = text.strip()
    if not text:
        return True
    lowered = text.lower()
    if lowered in {"secret", "password", "test", "none", "null", "todo"}:
        return True
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS) or text.startswith("<")


def _secret_text(value: SecretStr | None) -> str | None:
    return None if value is None else value.get_secret_value()


class Settings(BaseSettings):
    """All runtime configuration. Instantiated once per process via :func:`get_settings`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ runtime
    environment: Environment = "development"
    app_name: str = "A.R.M.X AI"
    log_level: str = "INFO"
    log_format: Literal["console", "json"] = "console"
    demo_insecure: bool = True
    api_host: str = "0.0.0.0"  # noqa: S104 - the container/network boundary provides the isolation
    api_port: int = 8000
    web_concurrency: int = Field(default=2, ge=1, le=32)
    backend_cors_origins: str = ""
    allow_plain_http_health_probe: bool = False
    trusted_proxy_ips: str = ""

    # ----------------------------------------------------------------- database
    database_url: str = "sqlite+aiosqlite:///./data/armx.db"
    database_pool_size: int = Field(default=10, ge=1, le=200)
    database_max_overflow: int = Field(default=20, ge=0, le=200)
    database_pool_timeout_seconds: float = Field(default=10.0, gt=0)
    database_pool_recycle_seconds: int = Field(default=1800, ge=0)
    database_statement_timeout_ms: int = Field(default=15000, ge=0)
    database_echo: bool = False
    db_auto_migrate: bool = True

    # ----------------------------------------------------------------- supabase
    supabase_url: str = ""
    supabase_anon_key: SecretStr | None = None
    supabase_service_role_key: SecretStr | None = None
    supabase_storage_bucket: str = "armx-assets"

    # --------------------------------------------------------------------- auth
    jwt_secret_key: SecretStr | None = None
    jwt_issuer: str = "armx-ai"
    jwt_audience: str = "armx-clients"
    access_token_ttl_seconds: int = Field(default=900, ge=60, le=900)
    refresh_token_ttl_seconds: int = Field(default=2_592_000, ge=300)
    auth_max_failed_logins: int = Field(default=5, ge=1, le=50)
    auth_lockout_seconds: int = Field(default=900, ge=30)
    password_min_length: int = Field(default=12, ge=8, le=128)
    encryption_key: SecretStr | None = None

    # ------------------------------------------------------------- email + SMTP
    email_delivery_mode: Literal["outbox", "smtp"] = "outbox"
    mail_from_address: str = "no-reply@thamjj13.top"
    mail_from_name: str = "A.R.M.X AI"
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = True
    smtp_timeout_seconds: float = Field(default=15.0, gt=0)
    email_token_ttl_seconds: int = Field(default=1800, ge=300, le=7200)

    # --------------------------------------------------------------- Google OAuth
    google_oauth_enabled: bool = False
    google_oauth_client_id: str = ""
    google_oauth_client_secret: SecretStr | None = None
    google_oauth_redirect_uri: str = "http://localhost:8000/auth/google/callback"
    google_oauth_allowed_domains: str = ""

    # ---------------------------------------------------------------------- LLM
    llm_provider: Literal["mock", "openai", "anthropic", "ollama", "openai_compatible"] = "mock"
    llm_timeout_seconds: float = Field(default=45.0, gt=0, le=300)
    llm_max_tokens: int = Field(default=1024, ge=64, le=8192)
    llm_temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    openai_api_key: SecretStr | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: SecretStr | None = None
    anthropic_base_url: str = "https://api.anthropic.com/v1"
    anthropic_model: str = "claude-sonnet-4-20250514"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    openai_compatible_base_url: str = ""
    openai_compatible_api_key: SecretStr | None = None
    openai_compatible_model: str = ""

    # ------------------------------------------------------------------ harness
    harness_max_tool_calls: int = Field(default=8, ge=1, le=32)
    harness_max_model_turns: int = Field(default=6, ge=1, le=24)
    harness_deadline_seconds: float = Field(default=120.0, ge=5, le=900)
    harness_tool_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    harness_max_result_chars: int = Field(default=8000, ge=256, le=100_000)
    harness_max_history_messages: int = Field(default=40, ge=2, le=200)

    # ----------------------------------------------------------------- security
    rate_limit_enabled: bool = True
    rate_limit_default: str = "120/minute"
    rate_limit_auth: str = "10/minute"
    rate_limit_tool_default: str = "60/hour"
    approval_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    approval_max_pending_per_user: int = Field(default=20, ge=1, le=500)
    kill_switch_allowed_tools: str = "health_status"

    # ------------------------------------------------------------ linked devices
    pairing_code_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    linked_device_owner_password_min_length: int = Field(default=12, ge=8, le=128)
    device_key_ttl_seconds: int = Field(default=31_536_000, ge=3600)
    pc_unlock_token_ttl_seconds: int = Field(default=30, ge=5, le=120)

    # -------------------------------------------------------------- smart home
    home_assistant_enabled: bool = False
    home_assistant_base_url: str = "http://home-assistant:8123"
    home_assistant_token: SecretStr | None = None
    home_assistant_entity_allowlist: str = ""
    mqtt_enabled: bool = False
    mqtt_host: str = "mosquitto"
    mqtt_port: int = Field(default=8883, ge=1, le=65535)
    mqtt_tls_enabled: bool = True
    mqtt_ca_file: str = ""
    mqtt_client_id: str = "armx-api"
    mqtt_username: str = ""
    mqtt_password: SecretStr | None = None
    mqtt_site: str = "home"
    mqtt_command_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    mqtt_keepalive_seconds: int = Field(default=30, ge=5, le=300)

    # ----------------------------------------------------------- web builder
    web_builder_enabled: bool = False
    github_enabled: bool = False
    github_token: SecretStr | None = None
    github_api_base: str = "https://api.github.com"
    github_repo_allowlist: str = ""
    github_deploy_branch: str = "main"
    vercel_enabled: bool = False
    vercel_token: SecretStr | None = None
    vercel_team_id: str = ""
    vercel_api_base: str = "https://api.vercel.com"
    vercel_project_allowlist: str = ""
    site_sandbox_dir: str = "./var/sites"
    site_max_files: int = Field(default=64, ge=1, le=1000)
    site_max_bytes: int = Field(default=1_048_576, ge=1024)
    site_preview_base_url: str = "http://localhost:8000/preview"

    # ------------------------------------------------------------------- n8n
    n8n_enabled: bool = False
    n8n_base_url: str = "http://n8n:5678"
    n8n_signing_secret: SecretStr | None = None
    n8n_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    n8n_workflows: str = ""

    # ------------------------------------------------------------------- MCP
    mcp_enabled: bool = False
    mcp_servers: str = ""
    mcp_max_result_bytes: int = Field(default=32_768, ge=512, le=1_048_576)
    mcp_timeout_seconds: float = Field(default=20.0, gt=0, le=120)

    # -------------------------------------------------------------- web search
    search_enabled: bool = False
    search_provider: Literal["none", "google", "bing"] = "none"
    google_search_api_key: SecretStr | None = None
    google_search_engine_id: str = ""
    bing_search_api_key: SecretStr | None = None
    search_max_results: int = Field(default=5, ge=1, le=20)
    search_timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    # ------------------------------------------------------------- mail (read)
    mail_enabled: bool = False
    imap_host: str = ""
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_username: str = ""
    imap_password: SecretStr | None = None
    imap_mailbox: str = "INBOX"
    imap_max_messages: int = Field(default=20, ge=1, le=100)

    # --------------------------------------------------------------- messaging
    messaging_enabled: bool = False
    whatsapp_enabled: bool = False
    whatsapp_access_token: SecretStr | None = None
    whatsapp_phone_number_id: str = ""
    whatsapp_verify_token: SecretStr | None = None
    whatsapp_app_secret: SecretStr | None = None
    messenger_enabled: bool = False
    messenger_page_access_token: SecretStr | None = None
    messenger_verify_token: SecretStr | None = None
    messenger_app_secret: SecretStr | None = None
    messaging_default_auto_send: bool = False

    # -------------------------------------------------------------- image edits
    image_provider: Literal["mock", "openai", "stability"] = "mock"
    image_api_key: SecretStr | None = None
    image_base_url: str = ""
    image_model: str = ""
    image_max_bytes: int = Field(default=5_242_880, ge=1024)
    image_max_pixels: int = Field(default=4_096_000, ge=1024)
    image_allowed_formats: str = "png,jpeg,webp"
    image_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    image_storage_dir: str = "./var/images"
    image_asset_ttl_seconds: int = Field(default=86_400, ge=60)

    # -------------------------------------------------------------------- jobs
    worker_enabled: bool = True
    #: Run the worker loop inside the API process. Convenient for local development and for a
    #: single-container deployment; the dedicated worker container sets this to false. Claiming
    #: is atomic either way, so two consumers cannot run the same job.
    worker_in_api: bool = True
    worker_concurrency: int = Field(default=2, ge=1, le=32)
    worker_poll_interval_seconds: float = Field(default=1.0, gt=0, le=30)
    job_timeout_seconds: int = Field(default=300, ge=5, le=3600)
    job_max_attempts: int = Field(default=3, ge=1, le=10)
    job_retention_days: int = Field(default=14, ge=1)

    # ------------------------------------------------------- audit and memory
    audit_retention_days: int = Field(default=365, ge=1)
    memory_retention_days: int = Field(default=180, ge=1)
    memory_max_items_per_user: int = Field(default=500, ge=1)

    # -------------------------------------------------------------- operations
    backup_dir: str = "./var/backups"
    backup_age_seconds: int = Field(default=0, ge=0)
    metrics_enabled: bool = True
    alert_webhook_url: str = ""
    secret_rotation_due_days: int = Field(default=90, ge=1)

    # --------------------------------------------------- derived (never from env)
    jwt_secret_was_generated: bool = False
    encryption_key_was_generated: bool = False

    # ------------------------------------------------------------- validators
    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
        upper = value.strip().upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {', '.join(sorted(allowed))}")
        return upper

    @model_validator(mode="after")
    def _validate_environment(self) -> Settings:
        problems: list[str] = []
        is_production = self.environment == "production"

        if is_production:
            if self.demo_insecure:
                problems.append("DEMO_INSECURE must be false in production (HTTPS is mandatory)")
            if self.uses_sqlite:
                problems.append(
                    "DATABASE_URL must point at PostgreSQL/Supabase in production, not SQLite"
                )
            if _is_missing(_secret_text(self.jwt_secret_key)):
                problems.append("JWT_SECRET_KEY is required")
            elif len(_secret_text(self.jwt_secret_key) or "") < 32:
                problems.append("JWT_SECRET_KEY must be at least 32 characters")
            if _is_missing(_secret_text(self.encryption_key)):
                problems.append("ENCRYPTION_KEY is required (Fernet key)")
            origins = self.cors_origin_list
            if not origins:
                problems.append("BACKEND_CORS_ORIGINS must list the real client origins")
            elif any(origin == "*" for origin in origins):
                problems.append("BACKEND_CORS_ORIGINS must not contain '*'")
            problems.extend(self._validate_integration_secrets())
        else:
            if _is_missing(_secret_text(self.jwt_secret_key)):
                self.jwt_secret_key = SecretStr(_secrets.token_urlsafe(48))
                self.jwt_secret_was_generated = True
            if _is_missing(_secret_text(self.encryption_key)):
                self.encryption_key = SecretStr(Fernet.generate_key().decode())
                self.encryption_key_was_generated = True

        if _secret_text(self.encryption_key) is not None:
            try:
                Fernet((_secret_text(self.encryption_key) or "").encode())
            except (ValueError, TypeError):
                problems.append("ENCRYPTION_KEY must be a valid Fernet key (44 char base64)")

        # Rate-limit specs are parsed at boot so a typo fails fast rather than
        # silently disabling a limit at request time.
        for spec_name in ("rate_limit_default", "rate_limit_auth", "rate_limit_tool_default"):
            try:
                parse_rate_limit(getattr(self, spec_name))
            except ValueError as exc:
                problems.append(f"{spec_name.upper()}: {exc}")

        # Allowlist specs are parsed at boot for the same reason.
        try:
            parse_csv(self.kill_switch_allowed_tools)
        except ValueError as exc:  # pragma: no cover - parse_csv cannot fail
            problems.append(f"KILL_SWITCH_ALLOWED_TOOLS: {exc}")
        try:
            parse_n8n_workflows(self.n8n_workflows)
        except ValueError as exc:
            problems.append(f"N8N_WORKFLOWS: {exc}")
        try:
            parse_mcp_servers(self.mcp_servers)
        except ValueError as exc:
            problems.append(f"MCP_SERVERS: {exc}")

        if problems:
            joined = "\n  - ".join(problems)
            raise ValueError(
                f"Invalid configuration for ENVIRONMENT={self.environment}:\n  - {joined}"
            )
        return self

    def _validate_integration_secrets(self) -> list[str]:
        """Production-only: an integration that is on must be fully configured."""
        problems: list[str] = []
        if self.llm_provider == "openai" and _is_missing(_secret_text(self.openai_api_key)):
            problems.append("OPENAI_API_KEY is required when LLM_PROVIDER=openai")
        if self.llm_provider == "anthropic" and _is_missing(_secret_text(self.anthropic_api_key)):
            problems.append("ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic")
        if self.llm_provider == "openai_compatible":
            if not self.openai_compatible_base_url:
                problems.append(
                    "OPENAI_COMPATIBLE_BASE_URL is required when LLM_PROVIDER=openai_compatible"
                )
            if _is_missing(_secret_text(self.openai_compatible_api_key)):
                problems.append(
                    "OPENAI_COMPATIBLE_API_KEY is required when LLM_PROVIDER=openai_compatible"
                )
        if self.email_delivery_mode == "smtp":
            if not self.smtp_host:
                problems.append("SMTP_HOST is required when EMAIL_DELIVERY_MODE=smtp")
            if _is_missing(_secret_text(self.smtp_password)):
                problems.append("SMTP_PASSWORD is required when EMAIL_DELIVERY_MODE=smtp")
        if self.google_oauth_enabled:
            if not self.google_oauth_client_id:
                problems.append("GOOGLE_OAUTH_CLIENT_ID is required when Google sign-in is enabled")
            if _is_missing(_secret_text(self.google_oauth_client_secret)):
                problems.append(
                    "GOOGLE_OAUTH_CLIENT_SECRET is required when Google sign-in is enabled"
                )
        if self.home_assistant_enabled:
            if not self.home_assistant_base_url:
                problems.append("HOME_ASSISTANT_BASE_URL is required when the HA adapter is on")
            if _is_missing(_secret_text(self.home_assistant_token)):
                problems.append("HOME_ASSISTANT_TOKEN is required when the HA adapter is on")
            if not self.home_assistant_entity_allowlist_set:
                problems.append(
                    "HOME_ASSISTANT_ENTITY_ALLOWLIST must name at least one entity: the LLM "
                    "may never invent an entity id"
                )
        if self.mqtt_enabled:
            if not self.mqtt_tls_enabled:
                problems.append("MQTT_TLS_ENABLED must be true outside a local/demo network")
            if _is_missing(self.mqtt_username) or _is_missing(_secret_text(self.mqtt_password)):
                problems.append("MQTT_USERNAME and MQTT_PASSWORD are required (per-device ACLs)")
            if not self.mqtt_ca_file:
                problems.append("MQTT_CA_FILE is required for TLS verification")
        if self.github_enabled:
            if _is_missing(_secret_text(self.github_token)):
                problems.append("GITHUB_TOKEN is required when the GitHub adapter is on")
            if len(self.github_repo_allowlist_set) != 1:
                problems.append(
                    "GITHUB_REPO_ALLOWLIST must name exactly one owner/repo: the deploy "
                    "credential is scoped to a single destination"
                )
        if self.vercel_enabled:
            if _is_missing(_secret_text(self.vercel_token)):
                problems.append("VERCEL_TOKEN is required when the Vercel adapter is on")
            if not self.vercel_project_allowlist_set:
                problems.append("VERCEL_PROJECT_ALLOWLIST must name the allowed project(s)")
        if self.n8n_enabled:
            if not self.n8n_base_url:
                problems.append("N8N_BASE_URL is required when the n8n bridge is on")
            if _is_missing(_secret_text(self.n8n_signing_secret)):
                problems.append("N8N_SIGNING_SECRET is required to sign webhook calls")
            if not self.n8n_workflow_specs:
                problems.append("N8N_WORKFLOWS must allowlist at least one workflow")
        if self.mcp_enabled and not self.mcp_server_specs:
            problems.append("MCP_SERVERS must allowlist at least one server when MCP is enabled")
        if self.search_enabled:
            if self.search_provider == "none":
                problems.append("SEARCH_PROVIDER must be google or bing when SEARCH_ENABLED=true")
            if self.search_provider == "google" and (
                _is_missing(_secret_text(self.google_search_api_key))
                or not self.google_search_engine_id
            ):
                problems.append("GOOGLE_SEARCH_API_KEY and GOOGLE_SEARCH_ENGINE_ID are required")
            if self.search_provider == "bing" and _is_missing(
                _secret_text(self.bing_search_api_key)
            ):
                problems.append("BING_SEARCH_API_KEY is required")
        if self.mail_enabled:
            if not self.imap_host or _is_missing(self.imap_username):
                problems.append("IMAP_HOST and IMAP_USERNAME are required when mail reading is on")
            if _is_missing(_secret_text(self.imap_password)):
                problems.append("IMAP_PASSWORD is required when mail reading is on")
        if self.messaging_enabled:
            if self.whatsapp_enabled and (
                _is_missing(_secret_text(self.whatsapp_access_token))
                or _is_missing(_secret_text(self.whatsapp_app_secret))
                or _is_missing(_secret_text(self.whatsapp_verify_token))
            ):
                problems.append(
                    "WHATSAPP_ACCESS_TOKEN, WHATSAPP_APP_SECRET and WHATSAPP_VERIFY_TOKEN are "
                    "required: unsigned webhooks must never be accepted"
                )
            if self.messenger_enabled and (
                _is_missing(_secret_text(self.messenger_page_access_token))
                or _is_missing(_secret_text(self.messenger_app_secret))
                or _is_missing(_secret_text(self.messenger_verify_token))
            ):
                problems.append(
                    "MESSENGER_PAGE_ACCESS_TOKEN, MESSENGER_APP_SECRET and "
                    "MESSENGER_VERIFY_TOKEN are required when Messenger is enabled"
                )
        if self.image_provider != "mock" and _is_missing(_secret_text(self.image_api_key)):
            problems.append(f"IMAGE_API_KEY is required when IMAGE_PROVIDER={self.image_provider}")
        if self.alert_webhook_url and not self.alert_webhook_url.startswith(
            ("https://", "http://")
        ):
            problems.append("ALERT_WEBHOOK_URL must be an http(s) URL")
        return problems

    # --------------------------------------------------------------- properties
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_local_dev(self) -> bool:
        return self.environment in {"development", "demo"}

    @property
    def uses_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def cors_origin_list(self) -> tuple[str, ...]:
        return parse_csv(self.backend_cors_origins)

    @property
    def trusted_proxy_list(self) -> tuple[str, ...]:
        return parse_csv(self.trusted_proxy_ips)

    @property
    def google_allowed_domain_set(self) -> tuple[str, ...]:
        return tuple(domain.lower() for domain in parse_csv(self.google_oauth_allowed_domains))

    @property
    def home_assistant_entity_allowlist_set(self) -> tuple[str, ...]:
        return parse_csv(self.home_assistant_entity_allowlist)

    @property
    def github_repo_allowlist_set(self) -> tuple[str, ...]:
        return parse_csv(self.github_repo_allowlist)

    @property
    def vercel_project_allowlist_set(self) -> tuple[str, ...]:
        return parse_csv(self.vercel_project_allowlist)

    @property
    def kill_switch_allowed_tool_set(self) -> tuple[str, ...]:
        return parse_csv(self.kill_switch_allowed_tools)

    @property
    def image_allowed_format_set(self) -> tuple[str, ...]:
        return tuple(fmt.lower() for fmt in parse_csv(self.image_allowed_formats))

    @property
    def n8n_workflow_specs(self) -> tuple[N8nWorkflowSpec, ...]:
        return parse_n8n_workflows(self.n8n_workflows)

    @property
    def n8n_workflow_by_name(self) -> dict[str, N8nWorkflowSpec]:
        return {spec.name: spec for spec in self.n8n_workflow_specs}

    @property
    def mcp_server_specs(self) -> tuple[McpServerSpec, ...]:
        return parse_mcp_servers(self.mcp_servers)

    @property
    def mcp_server_by_name(self) -> dict[str, McpServerSpec]:
        return {spec.name: spec for spec in self.mcp_server_specs}

    @property
    def default_rate_limit_spec(self) -> RateLimitSpec:
        return parse_rate_limit(self.rate_limit_default)

    @property
    def auth_rate_limit_spec(self) -> RateLimitSpec:
        return parse_rate_limit(self.rate_limit_auth)

    @property
    def tool_rate_limit_spec(self) -> RateLimitSpec:
        return parse_rate_limit(self.rate_limit_tool_default)

    @property
    def site_sandbox_path(self) -> Path:
        return Path(self.site_sandbox_dir)

    @property
    def image_storage_path(self) -> Path:
        return Path(self.image_storage_dir)

    # ------------------------------------------------------------------ helpers
    def secret(self, name: str) -> str | None:
        """Read a secret by attribute name; returns ``None`` when unset."""
        value = getattr(self, name, None)
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        if isinstance(value, str):
            return value or None
        return None

    def jwt_key(self) -> str:
        """Signing key, always present (ephemeral in development)."""
        return _secret_text(self.jwt_secret_key) or ""

    def encryption_fernet(self) -> Fernet:
        """Fernet instance for encrypted-secret-at-rest."""
        key = _secret_text(self.encryption_key)
        if not key:  # pragma: no cover - construction guarantees a key
            raise RuntimeError("ENCRYPTION_KEY is not configured")
        return Fernet(key.encode())

    def safe_summary(self) -> dict[str, Any]:
        """
        Non-secret configuration summary for startup logs, ``/health`` and the
        ``health_status`` tool. Never add a credential here.
        """
        return {
            "environment": self.environment,
            "app_name": self.app_name,
            "demo_insecure": self.demo_insecure,
            "database_dialect": self.database_url.split("://", 1)[0],
            "llm_provider": self.llm_provider,
            "email_delivery_mode": self.email_delivery_mode,
            "rate_limit_enabled": self.rate_limit_enabled,
            "worker_enabled": self.worker_enabled,
            "integrations": {
                "home_assistant": self.home_assistant_enabled,
                "mqtt": self.mqtt_enabled,
                "github": self.github_enabled,
                "vercel": self.vercel_enabled,
                "n8n": self.n8n_enabled,
                "mcp": self.mcp_enabled,
                "search": self.search_enabled,
                "mail_read": self.mail_enabled,
                "messaging": self.messaging_enabled,
                "image_provider": self.image_provider,
                "web_builder": self.web_builder_enabled,
                "google_oauth": self.google_oauth_enabled,
            },
            "secrets_generated_for_dev": {
                "jwt_secret_key": self.jwt_secret_was_generated,
                "encryption_key": self.encryption_key_was_generated,
            },
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()


def reset_settings_cache() -> None:
    """Testing hook: drop the cached singleton so env changes take effect."""
    get_settings.cache_clear()
