# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Settings validation: secrets, production hard-fails, and allowlist parsing."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.config import Settings
from app.core.ratelimit_spec import parse_rate_limit


def _production_kwargs() -> dict[str, object]:
    return {
        "environment": "production",
        "demo_insecure": False,
        "database_url": "postgresql://user:pw@db.example.com:5432/armx",
        "jwt_secret_key": "a-production-grade-secret-value-of-sufficient-length",
        "encryption_key": Fernet.generate_key().decode(),
        "backend_cors_origins": "https://app.example.com",
    }


def test_development_generates_ephemeral_secrets_once() -> None:
    settings = Settings(environment="development")
    assert settings.jwt_secret_was_generated is True
    assert settings.encryption_key_was_generated is True
    assert len(settings.jwt_key()) >= 32
    settings.encryption_fernet()  # must be a usable Fernet key


def test_production_accepts_a_complete_configuration() -> None:
    settings = Settings(**_production_kwargs())
    assert settings.is_production is True
    assert settings.uses_sqlite is False


@pytest.mark.parametrize(
    ("override", "expected_fragment"),
    [
        ({"demo_insecure": True}, "DEMO_INSECURE must be false"),
        ({"database_url": "sqlite+aiosqlite:///./x.db"}, "PostgreSQL/Supabase"),
        ({"jwt_secret_key": ""}, "JWT_SECRET_KEY is required"),
        ({"jwt_secret_key": "short"}, "at least 32 characters"),
        ({"encryption_key": ""}, "ENCRYPTION_KEY is required"),
        ({"backend_cors_origins": ""}, "BACKEND_CORS_ORIGINS"),
        ({"backend_cors_origins": "*"}, "must not contain '*'"),
    ],
)
def test_production_refuses_to_start_without_a_required_secret(
    override: dict[str, object], expected_fragment: str
) -> None:
    kwargs = _production_kwargs() | override
    with pytest.raises(ValueError) as excinfo:
        Settings(**kwargs)
    assert expected_fragment in str(excinfo.value)


@pytest.mark.parametrize(
    "placeholder",
    ["changeme", "your-secret-here", "<set-me>", "placeholder-value", "REPLACE_ME_PLEASE"],
)
def test_placeholder_secrets_are_treated_as_missing(placeholder: str) -> None:
    kwargs = _production_kwargs() | {"jwt_secret_key": placeholder + "x" * 20}
    with pytest.raises(ValueError, match="JWT_SECRET_KEY"):
        Settings(**kwargs)


def test_production_requires_tls_credentials_when_mqtt_is_on() -> None:
    with pytest.raises(ValueError) as excinfo:
        Settings(**(_production_kwargs() | {"mqtt_enabled": True}))
    message = str(excinfo.value)
    assert "MQTT_USERNAME" in message
    assert "MQTT_CA_FILE" in message


def test_production_requires_one_deploy_destination() -> None:
    with pytest.raises(ValueError, match="GITHUB_REPO_ALLOWLIST"):
        Settings(**(_production_kwargs() | {"github_enabled": True, "github_token": "x" * 40}))


def test_production_requires_webhook_secret_for_messaging() -> None:
    with pytest.raises(ValueError, match="WHATSAPP_APP_SECRET"):
        Settings(
            **(
                _production_kwargs()
                | {
                    "messaging_enabled": True,
                    "whatsapp_enabled": True,
                    "whatsapp_access_token": "x" * 40,
                }
            )
        )


def test_n8n_high_risk_workflow_must_declare_confirm() -> None:
    with pytest.raises(ValueError, match="confirm=true"):
        Settings(n8n_workflows="send|/webhook/send|high|false")


def test_mcp_server_spec_must_allowlist_tools() -> None:
    with pytest.raises(ValueError, match="allowlist at least one tool"):
        Settings(mcp_servers="github|http|https://mcp.example.com|")


def test_mcp_rejects_unknown_transport() -> None:
    with pytest.raises(ValueError, match="unsupported transport"):
        Settings(mcp_servers="github|stdio|https://mcp.example.com|search")


def test_safe_summary_never_contains_a_secret() -> None:
    settings = Settings(**(_production_kwargs()))
    summary = repr(settings.safe_summary())
    assert settings.jwt_key() not in summary
    assert (
        settings.encryption_key.get_secret_value() if settings.encryption_key else ""
    ) not in summary
    assert "password" not in summary.lower()


@pytest.mark.parametrize(
    ("spec", "count", "window"),
    [("30/hour", 30, 3600), ("10/minute", 10, 60), ("5/sec", 5, 1), ("100/day", 100, 86400)],
)
def test_rate_limit_specs_parse(spec: str, count: int, window: int) -> None:
    parsed = parse_rate_limit(spec)
    assert (parsed.count, parsed.window_seconds) == (count, window)


@pytest.mark.parametrize("spec", ["", "30", "hourly", "0/minute", "abc/hour"])
def test_invalid_rate_limit_specs_are_rejected(spec: str) -> None:
    with pytest.raises(ValueError):
        parse_rate_limit(spec)


def test_config_parses_operator_allowlists() -> None:
    settings = Settings(
        backend_cors_origins="https://a.example.com, https://b.example.com",
        github_repo_allowlist="owner/repository",
        vercel_project_allowlist="site-one,site-two",
        kill_switch_allowed_tools="health_status,get_device_state",
        n8n_workflows="daily|/webhook/daily|low|false,mailer|/webhook/mail|high|true",
        mcp_servers="github|http|https://mcp.example.com|search_repos;list_issues|15",
    )
    assert settings.cors_origin_list == ("https://a.example.com", "https://b.example.com")
    assert settings.github_repo_allowlist_set == ("owner/repository",)
    assert settings.vercel_project_allowlist_set == ("site-one", "site-two")
    assert settings.kill_switch_allowed_tool_set == ("health_status", "get_device_state")
    assert [spec.name for spec in settings.n8n_workflow_specs] == ["daily", "mailer"]
    assert settings.n8n_workflow_by_name["mailer"].confirm is True
    assert settings.mcp_server_by_name["github"].allows("list_issues") is True
    assert settings.mcp_server_by_name["github"].allows("delete_repo") is False
