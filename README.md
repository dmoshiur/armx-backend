# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

# armx-backend

A.R.M.X AI (Automated Resource Management eXtension) — Python/FastAPI backend for the
Flutter client in `dmoshiur/armx`. The implementation lives in
[`backend_python/`](backend_python/README.md); deployment runs on
[Render](https://render.com) with [Turso](https://turso.tech) for persistence and an external
MQTT broker for device transport. Setup, local/demo operation, operator provisioning, security
boundaries, and development checks are documented in the backend README. Unresolved schemas
and protocol additions are tracked in [`backend_python/API_GAPS.md`](backend_python/API_GAPS.md).

## Architecture

```
Flutter app (mobile / web)
      │  HTTPS + WSS
      ▼
Render Web Service  ──  uvicorn app.main:app, single instance, managed TLS
      │                        ▲
      │ libSQL over TLS 443    │ HTTP health probe + WebSocket traffic
      ▼                        │
Turso database                 │
                               │
ESP32 devices ── MQTT/TLS 8883 ─┴──► External MQTT broker ◄── backend connects outbound
                                        (managed or self-hosted; Render exposes no MQTT port)

Cloudinary: reserved for ordinary, non-biometric images only. Not integrated today, because
the backend has no image-upload feature; face images, face embeddings, and voice samples must
never leave the device (AGENTS.md rule 3).
```

* **Render** runs one Web Service with `render.yaml` as infrastructure-as-code: Python 3.12,
  `alembic upgrade head` on start, `healthCheckPath: /health`, and secrets declared
  `sync: false`. The filesystem is ephemeral, so no persistence depends on local disk.
* **Turso/libSQL** is the single database for users, devices, pairing, audit logs, intercom
  opt-in/log, activity rules, and MCP tool toggles. The URL and auth token come from
  environment variables only; tokens never appear in URLs or logs. Alembic manages the schema
  against the SQLite-compatible dialect.
* **MQTT** moved off the host: ESP32 devices publish/subscribe directly to an external broker
  over MQTT/TLS 8883, and the backend connects outbound to the same broker. The topic
  contract (`armx/{site}/{device}/cmd`, `armx/{site}/{device}/state`) and the server-side
  RiskPolicy gating are unchanged.
* **Cloudinary** is not wired up yet (no image-upload feature exists). When one arrives
  (avatar/device photos/admin assets), it may hold only ordinary images — never biometric
  data.

See [`docs/deploy-render.md`](docs/deploy-render.md) for the deployment runbook (Turso
database, env vars, first deploy, WebSocket verification, and the free-vs-paid tier decision).

## LLM provider (Ashna AI)

The chat router (`app/chat/`) is pluggable. The default provider is **Ashna AI's hosted
`ashna-x1` model** (`LLM_PROVIDER=ashna`); `ollama` and `openai_compatible` remain available
behind the same env var for local development and offline fallback.

Ashna AI's API is **OpenAI Chat Completions-compatible** (verified against the official
reference at <https://www.ashna.ai/api-docs>), so the adapter reuses the router's
OpenAI-compatible mapping rather than a bespoke client:

* Base URL: `https://api.ashna.ai/v1/api` → `POST /chat/completions`
* Auth: `Authorization: Bearer <ASHNA_API_KEY>` (the key is env-only and redacted from logs)
* Model id: `ashna-x1`
* Errors: OpenAI envelope `{ "error": { "message", "type", "code", "param" } }`

### Getting an API key

1. Sign in to <https://app.ashna.ai>.
2. Open **Account → API** (<https://app.ashna.ai/account?tab=api>) and create a key.
3. Set it as `ASHNA_API_KEY` in the environment (never in code or in the repo).

### Environment variables

| Variable          | Default                         | Purpose                                             |
| ----------------- | ------------------------------- | --------------------------------------------------- |
| `LLM_PROVIDER`    | `ashna`                         | `ashna`, `ollama`, or `openai_compatible`           |
| `ASHNA_API_KEY`   | —                               | Required when `LLM_PROVIDER=ashna`; startup fails with a clear error if unset (no silent fallback) |
| `ASHNA_BASE_URL`  | `https://api.ashna.ai/v1/api`   | Ashna OpenAI-compatible base URL                    |
| `ASHNA_MODEL`     | `ashna-x1`                      | Foundation model id sent as `model`                 |
| `LLM_TIMEOUT_SECONDS` | `60`                        | Per-request timeout for every provider              |

Retries: up to 3 attempts with exponential backoff, only for rate-limit (429), server
(5xx), and transport/timeout failures — never for 4xx client errors.

### Local development without an Ashna key

Set `LLM_PROVIDER=ollama` and run a local Ollama (Docker Compose wires the `ollama`
service container for you), or point `LLM_PROVIDER=openai_compatible` at any
OpenAI-compatible endpoint. This keeps the backend fully functional offline.

### Implemented behavior (tool calling & streaming)

* **Tool calling is native.** `ashna-x1` supports OpenAI-style client tools, so the router
  sends the MCP tool schemas as `tools` with `tool_choice: "auto"` and parses the returned
  `tool_calls`. No prompt-based JSON fallback is needed (the Ollama path also passes `tools`
  through). Proposed calls are still only proposals: nothing executes until the explicit
  confirmation step with fresh signed verification (AGENTS.md rule 6).
* **Streaming:** the Ashna adapter translates Ashna's OpenAI SSE stream (`stream: true`,
  chunks ending in `data: [DONE]`, tool-call deltas) into the router's internal token-stream
  shape. The WebSocket contract is unchanged either way: the client receives
  `assistant.token` events followed by `assistant.done` (and `tool.request` for proposals),
  exactly as before.
* **Untrusted content** fetched from GitHub/email/external sources is passed to the model
  only inside explicit `<<<UNTRUSTED_EXTERNAL_CONTENT>>>` delimiters as data, never merged
  into the system/instruction prompt (AGENTS.md rule 7; see
  `app/chat/llm_core.py:delimit_untrusted_content`).
