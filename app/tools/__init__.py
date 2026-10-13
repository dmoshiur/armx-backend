# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Tool modules.

One file per capability. Every module declares its tools with ``@tool(...)`` and is imported
once at startup by :func:`app.registry.discovery.discover_tools`. Nothing here is loaded from
disk, a URL, or user input at runtime: adding a capability means adding a reviewed module.

Rules that apply to every tool in this package:

* It receives validated arguments and a :class:`~app.registry.core.ToolContext`; it never sees
  the raw request, the model conversation, or a credential.
* It must not decide whether it is allowed to run. Scopes, risk tier, rate limits, approvals
  and the kill-switch are the Security Gateway's job, and they are checked before the handler
  is called.
* Content that originated outside the trust boundary is returned with ``untrusted=True`` so the
  harness can pass it to the model as data, never as instructions.
* Secrets never appear in output, logs or audit rows.
"""
