# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Deployment-configuration invariants.

The repository was flattened from ``backend_python/`` to the repository root (commit
20af65c) so that Render can build and run the service directly. These tests catch the exact
class of regression that followed that move — a stale ``rootDir``, a committed secret, or a
build/start command that no longer matches the app layout — without needing a live Render
account.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[1]

# Values supplied through the Render dashboard; they must never be committed.
DASHBOARD_PROVIDED_KEYS = {
    "PUBLIC_API_BASE_URL",
    "DATABASE_URL",
    "TURSO_AUTH_TOKEN",
    "JWT_SECRET_KEY",
    "BOOTSTRAP_ADMIN_PASSWORD",
    "CORS_ALLOWED_ORIGINS",
    "MQTT_HOST",
    "MQTT_USERNAME",
    "MQTT_PASSWORD",
    "ASHNA_API_KEY",
}


def _web_service() -> dict:
    data = yaml.safe_load((REPO_ROOT / "render.yaml").read_text(encoding="utf-8"))
    web_services = [service for service in data["services"] if service.get("type") == "web"]
    assert len(web_services) == 1, "expected exactly one Render web service"
    return web_services[0]


def test_blueprint_matches_the_flat_repository_layout() -> None:
    service = _web_service()
    assert service["runtime"] == "python"
    # The app, Alembic config, and pyproject.toml are at the repository root.
    assert "rootDir" not in service, (
        "render.yaml must not set rootDir: the backend lives at the repository root"
    )
    assert (REPO_ROOT / "pyproject.toml").is_file()
    assert (REPO_ROOT / "app/main.py").is_file()
    assert (REPO_ROOT / "alembic.ini").is_file()
    assert (REPO_ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.12"


def test_blueprint_build_start_and_health_contract() -> None:
    service = _web_service()
    assert service["healthCheckPath"] == "/health"
    assert "pip install" in service["buildCommand"]
    start_command = service["startCommand"]
    assert "alembic upgrade head" in start_command
    assert "uvicorn app.main:app" in start_command
    assert "$PORT" in start_command
    # Render terminates TLS and forwards plain HTTP; the app must trust that proxy hop.
    assert "--proxy-headers" in start_command
    assert "--ws-ping-interval" in start_command
    # Any WebSocket keepalive must be far below Render's 15-minute idle window.
    interval = int(re.search(r"--ws-ping-interval\s+(\d+)", start_command).group(1))
    assert 0 < interval < 15 * 60


def test_blueprint_prompts_for_every_dashboard_value_and_commits_no_secrets() -> None:
    service = _web_service()
    env_vars = {entry["key"]: entry for entry in service["envVars"]}
    for key in DASHBOARD_PROVIDED_KEYS:
        assert key in env_vars, f"{key} must be declared in render.yaml"
        assert env_vars[key].get("sync") is False, f"{key} must be declared with sync: false"
        assert "value" not in env_vars[key], f"{key} must not have a committed value"
    assert env_vars["LLM_PROVIDER"]["value"] == "ashna"
    assert env_vars["MQTT_PORT"]["value"] == "8883"
    assert env_vars["DEMO_INSECURE"]["value"] == "false"
    assert env_vars["ENVIRONMENT"]["value"] == "production"
    assert env_vars["ALLOW_PLAIN_HTTP_HEALTH_PROBE"]["value"] == "true"


def test_no_blueprint_or_documentation_path_targets_the_removed_directory() -> None:
    """Guard the flatten: no live path reference may point at ``backend_python/``."""

    path_reference = re.compile(r"backend_python/[A-Za-z0-9_]")
    documented = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "render.yaml",
        REPO_ROOT / "docker-compose.yml",
        REPO_ROOT / "API_GAPS.md",
        REPO_ROOT / "docs/deploy-render.md",
    ]
    for path in documented:
        assert path.is_file(), f"expected {path.name} to exist"
        assert not path_reference.search(path.read_text(encoding="utf-8")), (
            f"{path.name} references the removed backend_python/ layout"
        )


def test_deployment_runbook_exists_and_documents_the_chosen_broker() -> None:
    runbook = (REPO_ROOT / "docs/deploy-render.md").read_text(encoding="utf-8")
    assert "HiveMQ Cloud Serverless" in runbook
    assert "Turso" in runbook
    assert "Cloudinary" in runbook
