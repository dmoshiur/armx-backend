# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Tool registry: manifest validation, duplicate rejection, and discovery."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from app.config import Settings
from app.core.risk import Risk
from app.registry.core import (
    ToolInvocationError,
    ToolRegistry,
    ToolSpec,
    collected_specs,
    tool,
    validate_arguments,
)
from app.registry.discovery import discover_tools


class _In(BaseModel):
    text: str


class _Out(BaseModel):
    echoed: str


async def _default_handler(args: object, ctx: object) -> None:
    del args, ctx


def _spec(**overrides: object) -> ToolSpec:
    defaults: dict[str, object] = {
        "name": "unit_tool",
        "version": "1.0",
        "description": "test tool",
        "risk": Risk.LOW,
        "enabled": True,
        "input_schema": _In,
        "output_schema": _Out,
        "handler": _default_handler,
    }
    return ToolSpec(**(defaults | overrides))  # type: ignore[arg-type]


def test_duplicate_names_are_rejected() -> None:
    registry = ToolRegistry()
    registry.register(_spec(name="dupe"))
    with pytest.raises(ValueError, match="duplicate tool name"):
        registry.register(_spec(name="dupe"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"input_schema": dict},  # not a pydantic model
        {"output_schema": str},
        {"risk": "HIGH"},  # not a Risk member
        {"rate_limit": "sometimes"},
        {"name": "namespaced.tool"},
        {"name": "with spaces"},
        {"handler": "not-callable"},
    ],
)
def test_invalid_manifests_are_rejected_at_registration(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _spec(**overrides)


def test_high_risk_tools_must_require_confirmation() -> None:
    with pytest.raises(ValueError, match="must declare confirm=True"):
        _spec(risk=Risk.HIGH, confirm=False)
    spec = _spec(risk=Risk.HIGH, confirm=True)
    assert spec.risk is Risk.HIGH


def test_sync_handlers_are_rejected() -> None:
    def sync_handler(args: object, ctx: object) -> None:
        del args, ctx

    with pytest.raises(ValueError, match="must be async"):
        _spec(handler=sync_handler)


def test_registry_freezes_after_discovery() -> None:
    registry = ToolRegistry()
    registry.register(_spec(name="first"))
    registry.freeze()
    with pytest.raises(RuntimeError, match="frozen"):
        registry.register(_spec(name="second"))


async def test_validate_arguments_rejects_unknown_shapes() -> None:
    spec = _spec()
    with pytest.raises(ToolInvocationError) as excinfo:
        validate_arguments(spec, "not-an-object")
    assert excinfo.value.code == "tool_argument_invalid"

    with pytest.raises(ToolInvocationError) as excinfo:
        validate_arguments(spec, {"text": 123456})
    assert excinfo.value.code == "tool_argument_invalid"
    assert "text" in excinfo.value.message


def test_decorator_collects_specs_and_returns_the_handler() -> None:
    @tool(
        name="decorated_tool",
        version="2.0",
        description="declared for a test",
        risk=Risk.MEDIUM,
        input_schema=_In,
        output_schema=_Out,
        required_scopes=["tools:unit"],
        confirm=True,
        rate_limit="5/minute",
    )
    async def decorated_tool(args: _In, ctx: object) -> _Out:
        del ctx
        return _Out(echoed=args.text)

    assert decorated_tool.__name__ == "decorated_tool"
    # Collection is append-only for the life of the process: a declared tool is never removed,
    # so a second discovery pass cannot silently lose a capability.
    by_name = {spec.name: spec for spec in collected_specs()}
    assert "decorated_tool" in by_name
    assert by_name["decorated_tool"].required_scopes == ("tools:unit",)
    assert by_name["decorated_tool"].rate_limit_spec.count == 5


def test_discovery_finds_the_shipped_tools(registry: ToolRegistry) -> None:
    names = registry.names()
    assert "health_status" in names
    assert "mock_echo" in names
    # mock_echo ships disabled on purpose.
    assert "mock_echo" not in {spec.name for spec in registry.enabled()}
    # Every discovered tool must expose a JSON schema the LLM can be given.
    for spec in registry.all():
        assert spec.input_json_schema()["type"] == "object"
        assert isinstance(spec.manifest()["description"], str)


def test_discovery_is_repeatable_into_a_fresh_registry(tmp_settings: Settings) -> None:
    first = discover_tools(tmp_settings, target=ToolRegistry())
    second = discover_tools(tmp_settings, target=ToolRegistry())
    assert first.names() == second.names()
    assert first.snapshot_manifest() == second.snapshot_manifest()


def test_tools_for_a_disabled_integration_are_registered_but_not_enabled(
    tmp_settings: Settings,
) -> None:
    """A smart-home tool exists in the registry, but cannot run until HA is configured."""
    spec = ToolSpec(
        name="unit_ha_tool",
        version="1.0",
        description="needs Home Assistant",
        risk=Risk.LOW,
        enabled=True,
        input_schema=_In,
        output_schema=_Out,
        handler=_default_handler,
        integration="home_assistant",
    )
    discovered = discover_tools(tmp_settings, target=ToolRegistry(), extra_specs=(spec,))
    registered = discovered.get("unit_ha_tool")
    assert registered is not None
    assert registered.enabled is False  # registered, but not executable

    enabled_settings = tmp_settings.model_copy(
        update={"home_assistant_enabled": True, "home_assistant_entity_allowlist": "light.room"}
    )
    enabled_spec = discover_tools(enabled_settings, target=ToolRegistry(), extra_specs=(spec,)).get(
        "unit_ha_tool"
    )
    assert enabled_spec is not None
    assert enabled_spec.enabled is True


def test_unknown_integration_name_is_treated_as_unavailable(tmp_settings: Settings) -> None:
    """A typo in a manifest's ``integration`` must fail closed, not open."""
    spec = ToolSpec(
        name="unit_typo_tool",
        version="1.0",
        description="declares an integration that does not exist",
        risk=Risk.LOW,
        enabled=True,
        input_schema=_In,
        output_schema=_Out,
        handler=_default_handler,
        integration="not_a_real_integration",
    )
    assert (
        discover_tools(tmp_settings, target=ToolRegistry(), extra_specs=(spec,))
        .get("unit_typo_tool")
        .enabled
        is False
    )
