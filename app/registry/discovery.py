# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Tool discovery.

Only first-party modules under :mod:`app.tools` are imported, and only at startup. There is
no plugin upload, no entry-point scanning, no dynamic import of anything a user can influence:
in production, "new capability" means "new reviewed commit", never "new file dropped on disk".

Enabling is layered:

1. the manifest declares a default (``enabled=``),
2. the integration switch in settings can force it off (a tool for a disabled integration is
   registered but not executable),
3. the operator's ``tool_definitions.enabled`` row is the final say, enforced by the gateway.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable
from types import ModuleType
from typing import Final

from app.config import Settings
from app.core.logging import get_logger
from app.registry.core import _COLLECTED, ToolRegistry, ToolSpec, registry

__all__ = ["discover_tools", "integration_available"]

logger = get_logger("registry")

_TOOLS_PACKAGE: Final = "app.tools"

#: Integration switch that must be on for a tool to be executable, keyed by ``integration``.
_INTEGRATION_FLAGS: Final = {
    "home_assistant": "home_assistant_enabled",
    "mqtt": "mqtt_enabled",
    "github": "github_enabled",
    "vercel": "vercel_enabled",
    "n8n": "n8n_enabled",
    "mcp": "mcp_enabled",
    "search": "search_enabled",
    "mail": "mail_enabled",
    "messaging": "messaging_enabled",
    "image": "image_available",
    "web_builder": "web_builder_available",
    "smtp": "email_available",
}


def integration_available(settings: Settings, integration: str | None) -> bool:
    """Whether the integration behind a tool is configured and switched on."""
    if integration is None:
        return True
    attribute = _INTEGRATION_FLAGS.get(integration)
    if attribute is None:
        logger.warning(
            "tool declares unknown integration %r; treating it as unavailable", integration
        )
        return False
    if attribute == "image_available":
        # Always available: with the mock provider the tool runs end to end without an
        # external service, and the adapter refuses to call a real provider without a key.
        return True
    if attribute == "web_builder_available":
        return settings.web_builder_enabled
    if attribute == "email_available":
        # Both delivery modes are valid: "outbox" records the message for review and tests.
        return True
    return bool(getattr(settings, attribute, False))


def _import_tool_modules() -> list[str]:
    """Import every module in :mod:`app.tools` (first-party only) and return their names."""
    package = importlib.import_module(_TOOLS_PACKAGE)
    imported: list[str] = []
    for module_info in pkgutil.iter_modules(package.__path__):
        if module_info.name.startswith("_") or module_info.name == "routes":
            continue
        module: ModuleType = importlib.import_module(f"{_TOOLS_PACKAGE}.{module_info.name}")
        imported.append(module.__name__)
    return imported


def discover_tools(
    settings: Settings,
    *,
    target: ToolRegistry | None = None,
    extra_specs: Iterable[ToolSpec] = (),
) -> ToolRegistry:
    """
    Populate (or repopulate) a tool registry.

    Idempotent: modules are imported once per process, so calling this again with a fresh
    ``target`` re-registers the already-collected specs without re-importing them. ``extra_specs``
    adds manifests explicitly (used by tests and by adapters that build specs at runtime from an
    allowlist); duplicate names are still rejected by the registry.
    """
    destination = target or registry
    # Importing is idempotent: modules load once per process and their decorators populate
    # _COLLECTED. A second call re-registers the same specs into a fresh registry.
    imported = _import_tool_modules()

    destination._tools.clear()
    destination._frozen = False
    disabled_by_integration: list[str] = []
    collected = list(_COLLECTED.values()) + list(extra_specs)
    for spec in sorted(collected, key=lambda item: item.name):
        effective = spec.enabled and integration_available(settings, spec.integration)
        if spec.enabled and not effective:
            disabled_by_integration.append(spec.name)
        destination.register(
            ToolSpec(
                name=spec.name,
                version=spec.version,
                description=spec.description,
                risk=spec.risk,
                enabled=effective,
                input_schema=spec.input_schema,
                output_schema=spec.output_schema,
                handler=spec.handler,
                required_scopes=spec.required_scopes,
                confirm=spec.confirm,
                rate_limit=spec.rate_limit,
                dry_run_supported=spec.dry_run_supported,
                category=spec.category,
                integration=spec.integration,
                timeout_seconds=spec.timeout_seconds,
            )
        )
    destination.freeze()

    logger.info(
        "registry discovered module_count=%d tool_count=%d disabled_by_integration=%d",
        len(imported),
        len(destination),
        len(disabled_by_integration),
    )
    if disabled_by_integration:
        logger.info(
            "tools registered but not executable (integration off): %s",
            ", ".join(sorted(disabled_by_integration)),
        )
    return destination


def reload_registry_for_tests(settings: Settings) -> ToolRegistry:
    """Test helper: rebuild the process registry from scratch."""
    fresh = ToolRegistry()
    return discover_tools(settings, target=fresh)
