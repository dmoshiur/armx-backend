# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
``mock_echo`` - a deterministic developer tool.

Registered **disabled** on purpose: it exists so the tool-toggle, dry-run, rate-limit and
approval paths can be exercised end to end without touching an integration, and an operator
must explicitly enable it (per user, per role, or globally) before it can be called at all.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.core.crypto import sha256_hex
from app.core.errors import ErrorCode
from app.core.risk import Risk
from app.registry import ToolContext, ToolInvocationError, ToolResult, tool


class MockEchoInput(BaseModel):
    text: str = Field(min_length=1, max_length=500, description="Text to echo back.")
    uppercase: bool = Field(default=False, description="Return the text upper-cased.")


class MockEchoOutput(BaseModel):
    echo: str
    length: int
    digest: str
    dry_run: bool


@tool(
    name="mock_echo",
    version="1.0",
    description=(
        "Developer tool: echoes text back and returns its digest. Disabled by default; enable "
        "it from the admin tool toggles to exercise the gateway without a live integration."
    ),
    risk=Risk.LOW,
    enabled=False,
    input_schema=MockEchoInput,
    output_schema=MockEchoOutput,
    required_scopes=["tools:mock"],
    confirm=False,
    rate_limit="30/minute",
    dry_run_supported=True,
    category="developer",
)
async def mock_echo(args: MockEchoInput, ctx: ToolContext) -> ToolResult:
    if ctx.settings.is_production:
        # A developer convenience must not survive into production, whatever the toggles say.
        raise ToolInvocationError(
            ErrorCode.INTEGRATION_DISABLED, "mock_echo is not available in production"
        )
    text = args.text.upper() if args.uppercase else args.text
    output = MockEchoOutput(
        echo=text,
        length=len(text),
        digest=sha256_hex(text),
        dry_run=ctx.dry_run,
    )
    return ToolResult(
        summary=f"echoed {output.length} characters",
        data=output.model_dump(mode="json"),
        dry_run=ctx.dry_run,
    )
