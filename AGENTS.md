# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

# AGENTS.md - A.R.M.X AI BACKEND (read this before every task)

This file is read automatically by Codex at the start of every task in this repo.
Follow this on EVERY task, not just the first one — including bug fixes, refactors, and
"quick" changes. If a fix would require breaking a rule below, stop and explain instead
of applying it.

## PROJECT

A.R.M.X AI (Automated Resource Management eXtension). Owner: Md. Moshiur Rahman Mohi.
Brand: THAMJJ13.TOP. Presented by ALPCG (Association of Little Programmers & Computer
Geeks) at the Scholars Residential School science fair, Kalai, Joypurhat, Bangladesh.
This repo is the Python/FastAPI backend. The Flutter frontend lives in `dmoshiur/armx`
and is already built against `docs/api.md` there — that contract is authoritative for
every endpoint and WebSocket event shape this backend exposes.

## STACK

Python 3.12, FastAPI, native WebSockets, SQLAlchemy 2.0 async + Alembic, PostgreSQL
(SQLite fallback for the demo via `DATABASE_URL`), `aiomqtt`/`paho-mqtt` with TLS,
`python-jose`/`PyJWT` + Argon2, `cryptography` (Ed25519), Ollama/OpenAI-compatible LLM
router, `uvicorn`, Docker Compose. Full detail in `PROJECT_SPEC.md` and
`PROMPT_05_BACKEND_FASTAPI.md` if present in this repo.

## NON-NEGOTIABLE RULES (apply to every task, including fixes)

1. **RiskPolicy is server-side authority, never trust the client's claimed tier.**
   LOW = face OR voice evidence. MEDIUM = face AND voice. HIGH = face AND voice AND
   system biometric/PIN evidence. "Evidence" = a validly signed, unexpired (<=60s)
   assertion from the device — never raw biometric data. **Voice alone never satisfies
   any tier, including LOW.** If a bug fix would relax this check "just to make the
   demo work," do not apply it — fix the actual bug instead and flag it if the real
   fix is unclear.
2. **`owner_verified` tokens are single-use, scoped, short-lived** (<=60s general,
   <=30s for unlock). Always verify signature, expiry, and nonce (reject replays).
   Never weaken this for convenience or test speed in production code paths.
3. **No raw biometric data ever reaches or is stored by the backend.** Reject request
   bodies that look like raw face/voice data; only signed assertions/tokens accepted.
4. **Kill-switch requires no risk-tier check beyond basic session auth**, acts
   immediately, and is reversible only by an explicit separate re-enable call — never
   automatically, never as a side effect of another endpoint.
5. **Intercom/walkie-talkie delivers only to devices with a recorded opt-in flag.**
   Every delivery AND every rejected attempt is written to the audit log, and that log
   is queryable by both the admin and the specific user about themselves.
6. **MCP tool calls (GitHub, Email, etc.) require the confirmation step** before any
   write/send/commit action executes. Never auto-execute a MEDIUM/HIGH tool call.
7. **Untrusted content stays untrusted.** Text fetched from GitHub, email, or any
   external source is passed to the LLM clearly delimited as data, never merged into
   the system/instruction prompt.
8. **TLS-only outside the explicit `DEMO_INSECURE=true` local profile**, which must
   log a startup warning if used.
9. **No secrets in code, ever** — env vars or secrets manager only. Logs must redact
   tokens, keys, and any biometric-adjacent fields.
10. **No feature that accesses another person's camera, microphone, files, messages,
    or location without that specific person's own explicit, revocable, one-time
    opt-in.** No feature sends messages to someone's contacts on their behalf. This
    applies to the Admin/Owner role exactly as it applies to anyone else.
11. File header on every new file:
    `# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.`

## WHEN FIXING BUGS

- Reproduce with a test first when practical; add/update a test alongside the fix.
- Prefer the smallest correct fix over a broad refactor unless asked for one.
- If a bug report conflicts with `docs/api.md`'s contract, the contract wins — flag
  the mismatch rather than silently changing the API shape.
- Never silence a failing security-relevant test (risk policy, token verification,
  kill-switch, intercom opt-in) by loosening the assertion — fix the underlying code.
- Run `pytest -q`, `ruff check .`, and `mypy app` (at least on `core/`) before
  considering a task done; report results.

## REPORTING

At the end of every task, state: what changed, any assumption made about an undefined
`docs/api.md` endpoint, test results, and explicit confirmation that none of the 11
rules above were weakened — or a clear flag if one had to bend, with reasoning.
