# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Integration allowlist specs.

Parsing lives here rather than in :mod:`app.config` so that integration adapters can
import the specs without importing the settings singleton (no import cycles).
Note: nothing in this module imports settings, models, or adapters.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.risk import Risk

__all__ = [
    "McpServerSpec",
    "N8nWorkflowSpec",
    "parse_csv",
    "parse_mcp_servers",
    "parse_n8n_workflows",
]

_ALLOWED_MCP_TRANSPORTS = frozenset({"http", "sse"})


def parse_csv(value: str | None) -> tuple[str, ...]:
    """Split a comma-separated env value into a de-duplicated, ordered tuple."""
    if not value:
        return ()
    seen: dict[str, None] = {}
    for raw in value.split(","):
        item = raw.strip()
        if item:
            seen.setdefault(item, None)
    return tuple(seen)


@dataclass(frozen=True, slots=True)
class N8nWorkflowSpec:
    """
    One allowlisted n8n workflow.

    ``risk`` and ``confirm`` are declared by the operator, not inferred: a workflow
    that sends, posts, uploads, or deletes must be declared HIGH with ``confirm``.
    """

    name: str
    path: str
    risk: Risk
    confirm: bool

    @property
    def url_path(self) -> str:
        return self.path if self.path.startswith("/") else f"/{self.path}"


@dataclass(frozen=True, slots=True)
class McpServerSpec:
    """One explicitly allowlisted MCP server and the capabilities it may expose."""

    name: str
    transport: str
    url: str
    allowed_tools: tuple[str, ...]
    timeout_seconds: float | None = None

    def allows(self, tool_name: str) -> bool:
        return tool_name in self.allowed_tools


def parse_n8n_workflows(value: str | None) -> tuple[N8nWorkflowSpec, ...]:
    """
    Parse ``name|/webhook/path|risk|confirm`` entries separated by commas.

    Malformed entries raise ``ValueError``: a half-configured deploy allowlist is a
    startup-time error, never a silently skipped workflow.
    """
    specs: list[N8nWorkflowSpec] = []
    names: set[str] = set()
    for entry in parse_csv(value):
        parts = [part.strip() for part in entry.split("|")]
        if len(parts) != 4:
            raise ValueError(
                f"invalid N8N_WORKFLOWS entry {entry!r}: expected name|path|risk|confirm"
            )
        name, path, risk_text, confirm_text = parts
        if not name or not path:
            raise ValueError(f"invalid N8N_WORKFLOWS entry {entry!r}: name and path are required")
        if not path.startswith("/"):
            raise ValueError(f"invalid N8N_WORKFLOWS entry {entry!r}: path must start with '/'")
        if name in names:
            raise ValueError(f"duplicate n8n workflow name {name!r}")
        risk = Risk.parse(risk_text)
        confirm = confirm_text.strip().lower() in {"1", "true", "yes", "on"}
        if risk is Risk.HIGH and not confirm:
            raise ValueError(f"n8n workflow {name!r} is HIGH risk and must declare confirm=true")
        names.add(name)
        specs.append(N8nWorkflowSpec(name=name, path=path, risk=risk, confirm=confirm))
    return tuple(specs)


def parse_mcp_servers(value: str | None) -> tuple[McpServerSpec, ...]:
    """Parse ``name|transport|url|tool1;tool2|timeout`` entries separated by commas."""
    specs: list[McpServerSpec] = []
    names: set[str] = set()
    for entry in parse_csv(value):
        parts = [part.strip() for part in entry.split("|")]
        if len(parts) not in {4, 5}:
            raise ValueError(
                f"invalid MCP_SERVERS entry {entry!r}: expected name|transport|url|tools[|timeout]"
            )
        name, transport, url = parts[0], parts[1].lower(), parts[2]
        allowed = tuple(tool.strip() for tool in parts[3].split(";") if tool.strip())
        timeout = float(parts[4]) if len(parts) == 5 and parts[4] else None
        if not name or name in names:
            raise ValueError(f"invalid or duplicate MCP server name {name!r}")
        if transport not in _ALLOWED_MCP_TRANSPORTS:
            raise ValueError(
                f"MCP server {name!r} uses unsupported transport {transport!r}; "
                f"allowed: {', '.join(sorted(_ALLOWED_MCP_TRANSPORTS))}"
            )
        if not url.startswith("https://") and not url.startswith("http://"):
            raise ValueError(f"MCP server {name!r} url must be http(s)")
        if not allowed:
            raise ValueError(f"MCP server {name!r} must allowlist at least one tool")
        if timeout is not None and timeout <= 0:
            raise ValueError(f"MCP server {name!r} timeout must be positive")
        names.add(name)
        specs.append(
            McpServerSpec(
                name=name,
                transport=transport,
                url=url,
                allowed_tools=allowed,
                timeout_seconds=timeout,
            )
        )
    return tuple(specs)
