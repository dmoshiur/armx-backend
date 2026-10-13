# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The assistant harness.

Turns a user message plus a model into a bounded sequence of *proposed* tool calls, each of which
the Security Gateway independently allows or refuses. The model never executes anything; see
:mod:`app.harness.runner` for the loop and :mod:`app.harness.prompts` for the trust boundary as it
is stated to the model.
"""

from app.harness.prompts import build_system_prompt, tool_definitions
from app.harness.runner import HarnessEvent, HarnessLimits, HarnessTurn, run_turn

__all__ = [
    "HarnessEvent",
    "HarnessLimits",
    "HarnessTurn",
    "build_system_prompt",
    "run_turn",
    "tool_definitions",
]
