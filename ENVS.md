# A.R.M.X AI — Backend: Environment Variables

> Complete list of every environment variable used by this project.
> Canonical source: [`.env.example`](.env.example) (validated by `app/config.py`).
> Copy it to get started: `cp .env.example .env` — never commit a real `.env` or secret.

**167 variables** are defined in `.env.example`, grouped below, plus a handful of
extra variables that only exist in `app/config.py`, Docker Compose, or the backup scripts
(listed at the end). Values shown are the defaults/placeholders from `.env.example`;
an empty value means *unset* (no default — a secret you must supply, or an optional feature).

## Contents

- [Core runtime](#core-runtime)
- [Database](#database)
- [Supabase (optional)](#supabase-optional)
- [Auth](#auth)
- [Email + SMTP](#email--smtp)
- [Google OAuth](#google-oauth)
- [LLM (planner)](#llm-planner)
- [Harness bounds](#harness-bounds)
- [Security gateway](#security-gateway)
- [Linked devices](#linked-devices)
- [Smart home (Home Assistant / MQTT)](#smart-home-home-assistant--mqtt)
- [Web builder (GitHub / Vercel)](#web-builder-github--vercel)
- [n8n bridge](#n8n-bridge)
- [MCP (allowlist)](#mcp-allowlist)
- [Web search](#web-search)
- [Mail — read-only (IMAP)](#mail--read-only-imap)
- [Messaging APIs (WhatsApp / Messenger)](#messaging-apis-whatsapp--messenger)
- [Image edits](#image-edits)
- [Jobs (worker process)](#jobs-worker-process)
- [Audit + memory hygiene](#audit--memory-hygiene)
- [Operations](#operations)
- [Config-only variables (not in `.env.example`)](#config-only-variables-not-in-envexample)
- [Docker Compose-only variables](#docker-compose-only-variables)
- [Backup/restore script variables](#backuprestore-script-variables)
- [Required in production](#required-in-production)
- [Minimal local `.env`](#minimal-local-env)

## Core runtime

| Variable | Default / placeholder | Notes |
|---|---|---|
| `ENVIRONMENT` | `development` | development \| demo \| staging \| production |
| `APP_NAME` | `A.R.M.X AI` | — |
| `LOG_LEVEL` | `INFO` | DEBUG \| INFO \| WARNING \| ERROR |
| `LOG_FORMAT` | `console` | console (human) \| json (shipped to a log drain) |
| `DEMO_INSECURE` | `true` | allows plain HTTP. Forbidden in production. |
| `API_HOST` | `0.0.0.0` | — |
| `API_PORT` | `8000` | — |
| `WEB_CONCURRENCY` | `2` | uvicorn worker processes behind nginx |
| `BACKEND_CORS_ORIGINS` | _(empty)_ | comma-separated browser origins, e.g. https://app.example.com |
| `ALLOW_PLAIN_HTTP_HEALTH_PROBE` | `false` | liveness probes only; never on a public host |
| `TRUSTED_PROXY_IPS` | _(empty)_ | e.g. 172.16.0.0/12 when behind nginx/compose |

## Database

| Variable | Default / placeholder | Notes |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/armx.db` | — |
| `DATABASE_POOL_SIZE` | `10` | — |
| `DATABASE_MAX_OVERFLOW` | `20` | — |
| `DATABASE_POOL_TIMEOUT_SECONDS` | `10` | — |
| `DATABASE_POOL_RECYCLE_SECONDS` | `1800` | — |
| `DATABASE_STATEMENT_TIMEOUT_MS` | `15000` | — |
| `DATABASE_ECHO` | `false` | — |
| `DB_AUTO_MIGRATE` | `true` | run `alembic upgrade head` on container start |

## Supabase (optional)

| Variable | Default / placeholder | Notes |
|---|---|---|
| `SUPABASE_URL` | _(empty)_ | — |
| `SUPABASE_ANON_KEY` | _(empty)_ | — |
| `SUPABASE_SERVICE_ROLE_KEY` | _(empty)_ | — |
| `SUPABASE_STORAGE_BUCKET` | `armx-assets` | — |

## Auth

| Variable | Default / placeholder | Notes |
|---|---|---|
| `JWT_SECRET_KEY` | _(empty)_ | — |
| `JWT_ISSUER` | `armx-ai` | — |
| `JWT_AUDIENCE` | `armx-clients` | — |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | <= 15 minutes, hard ceiling enforced |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` | 30 days, rotated on every use |
| `AUTH_MAX_FAILED_LOGINS` | `5` | — |
| `AUTH_LOCKOUT_SECONDS` | `900` | — |
| `PASSWORD_MIN_LENGTH` | `12` | — |
| `ENCRYPTION_KEY` | _(empty)_ | — |

## Email + SMTP

| Variable | Default / placeholder | Notes |
|---|---|---|
| `EMAIL_DELIVERY_MODE` | `outbox` | outbox \| smtp |
| `MAIL_FROM_ADDRESS` | `no-reply@thamjj13.top` | — |
| `MAIL_FROM_NAME` | `A.R.M.X AI` | — |
| `SMTP_HOST` | _(empty)_ | — |
| `SMTP_PORT` | `587` | — |
| `SMTP_USERNAME` | _(empty)_ | — |
| `SMTP_PASSWORD` | _(empty)_ | — |
| `SMTP_STARTTLS` | `true` | — |
| `SMTP_TIMEOUT_SECONDS` | `15` | — |
| `EMAIL_TOKEN_TTL_SECONDS` | `1800` | email verification + password reset (15-30 min) |

## Google OAuth

| Variable | Default / placeholder | Notes |
|---|---|---|
| `GOOGLE_OAUTH_ENABLED` | `false` | — |
| `GOOGLE_OAUTH_CLIENT_ID` | _(empty)_ | — |
| `GOOGLE_OAUTH_CLIENT_SECRET` | _(empty)_ | — |
| `GOOGLE_OAUTH_REDIRECT_URI` | `http://localhost:8000/auth/google/callback` | — |
| `GOOGLE_OAUTH_ALLOWED_DOMAINS` | _(empty)_ | comma separated; empty = any verified Google account |

## LLM (planner)

| Variable | Default / placeholder | Notes |
|---|---|---|
| `LLM_PROVIDER` | `mock` | mock \| openai \| anthropic \| ollama \| openai_compatible |
| `LLM_TIMEOUT_SECONDS` | `45` | — |
| `LLM_MAX_TOKENS` | `1024` | — |
| `LLM_TEMPERATURE` | `0.2` | — |
| `OPENAI_API_KEY` | _(empty)_ | — |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | — |
| `OPENAI_MODEL` | `gpt-4o-mini` | — |
| `ANTHROPIC_API_KEY` | _(empty)_ | — |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com/v1` | — |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-20250514` | — |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | — |
| `OLLAMA_MODEL` | `qwen2.5:3b` | — |
| `OPENAI_COMPATIBLE_BASE_URL` | _(empty)_ | — |
| `OPENAI_COMPATIBLE_API_KEY` | _(empty)_ | — |
| `OPENAI_COMPATIBLE_MODEL` | _(empty)_ | — |

## Harness bounds

| Variable | Default / placeholder | Notes |
|---|---|---|
| `HARNESS_MAX_TOOL_CALLS` | `8` | per session (hard cap) |
| `HARNESS_MAX_MODEL_TURNS` | `6` | — |
| `HARNESS_DEADLINE_SECONDS` | `120` | — |
| `HARNESS_TOOL_TIMEOUT_SECONDS` | `30` | — |
| `HARNESS_MAX_RESULT_CHARS` | `8000` | tool output truncation before it reaches the model |
| `HARNESS_MAX_HISTORY_MESSAGES` | `40` | — |

## Security gateway

| Variable | Default / placeholder | Notes |
|---|---|---|
| `RATE_LIMIT_ENABLED` | `true` | — |
| `RATE_LIMIT_DEFAULT` | `120/minute` | global per-actor default |
| `RATE_LIMIT_AUTH` | `10/minute` | login/signup/forgot-password per IP |
| `RATE_LIMIT_TOOL_DEFAULT` | `60/hour` | — |
| `APPROVAL_TTL_SECONDS` | `300` | fresh, exact-action approvals expire quickly |
| `APPROVAL_MAX_PENDING_PER_USER` | `20` | — |
| `KILL_SWITCH_ALLOWED_TOOLS` | `health_status` | tools that still answer while the kill-switch is engaged |

## Linked devices

| Variable | Default / placeholder | Notes |
|---|---|---|
| `PAIRING_CODE_TTL_SECONDS` | `600` | — |
| `LINKED_DEVICE_OWNER_PASSWORD_MIN_LENGTH` | `12` | — |
| `DEVICE_KEY_TTL_SECONDS` | `31536000` | — |
| `PC_UNLOCK_TOKEN_TTL_SECONDS` | `30` | device-held signed unlock tokens are shorter still |

## Smart home (Home Assistant / MQTT)

| Variable | Default / placeholder | Notes |
|---|---|---|
| `HOME_ASSISTANT_ENABLED` | `false` | — |
| `HOME_ASSISTANT_BASE_URL` | `http://home-assistant:8123` | — |
| `HOME_ASSISTANT_TOKEN` | _(empty)_ | — |
| `HOME_ASSISTANT_ENTITY_ALLOWLIST` | `light.living_room,switch.fan` | — |
| `MQTT_ENABLED` | `false` | — |
| `MQTT_HOST` | `mosquitto` | — |
| `MQTT_PORT` | `8883` | — |
| `MQTT_TLS_ENABLED` | `true` | — |
| `MQTT_CA_FILE` | `/run/armx/mqtt-ca/ca.crt` | — |
| `MQTT_CLIENT_ID` | `armx-api` | — |
| `MQTT_USERNAME` | _(empty)_ | — |
| `MQTT_PASSWORD` | _(empty)_ | — |
| `MQTT_SITE` | `home` | — |
| `MQTT_COMMAND_TIMEOUT_SECONDS` | `10` | — |
| `MQTT_KEEPALIVE_SECONDS` | `30` | — |

## Web builder (GitHub / Vercel)

| Variable | Default / placeholder | Notes |
|---|---|---|
| `WEB_BUILDER_ENABLED` | `false` | — |
| `GITHUB_ENABLED` | `false` | — |
| `GITHUB_TOKEN` | _(empty)_ | — |
| `GITHUB_API_BASE` | `https://api.github.com` | — |
| `GITHUB_REPO_ALLOWLIST` | _(empty)_ | exactly one owner/repo per deployment, e.g. dmoshiur/armx-sites |
| `GITHUB_DEPLOY_BRANCH` | `main` | — |
| `VERCEL_ENABLED` | `false` | — |
| `VERCEL_TOKEN` | _(empty)_ | — |
| `VERCEL_TEAM_ID` | _(empty)_ | — |
| `VERCEL_API_BASE` | `https://api.vercel.com` | — |
| `VERCEL_PROJECT_ALLOWLIST` | _(empty)_ | e.g. armx-sites |
| `SITE_SANDBOX_DIR` | `./var/sites` | — |
| `SITE_MAX_FILES` | `64` | — |
| `SITE_MAX_BYTES` | `1048576` | — |
| `SITE_PREVIEW_BASE_URL` | `http://localhost:8000/preview` | — |

## n8n bridge

| Variable | Default / placeholder | Notes |
|---|---|---|
| `N8N_ENABLED` | `false` | — |
| `N8N_BASE_URL` | `http://n8n:5678` | — |
| `N8N_SIGNING_SECRET` | _(empty)_ | — |
| `N8N_TIMEOUT_SECONDS` | `30` | — |
| `N8N_WORKFLOWS` | _(empty)_ | — |

## MCP (allowlist)

| Variable | Default / placeholder | Notes |
|---|---|---|
| `MCP_ENABLED` | `false` | — |
| `MCP_SERVERS` | _(empty)_ | — |
| `MCP_MAX_RESULT_BYTES` | `32768` | — |
| `MCP_TIMEOUT_SECONDS` | `20` | — |

## Web search

| Variable | Default / placeholder | Notes |
|---|---|---|
| `SEARCH_ENABLED` | `false` | — |
| `SEARCH_PROVIDER` | `none` | none \| google \| bing |
| `GOOGLE_SEARCH_API_KEY` | _(empty)_ | — |
| `GOOGLE_SEARCH_ENGINE_ID` | _(empty)_ | — |
| `BING_SEARCH_API_KEY` | _(empty)_ | — |
| `SEARCH_MAX_RESULTS` | `5` | — |
| `SEARCH_TIMEOUT_SECONDS` | `10` | — |

## Mail — read-only (IMAP)

| Variable | Default / placeholder | Notes |
|---|---|---|
| `MAIL_ENABLED` | `false` | — |
| `IMAP_HOST` | _(empty)_ | — |
| `IMAP_PORT` | `993` | — |
| `IMAP_USERNAME` | _(empty)_ | — |
| `IMAP_PASSWORD` | _(empty)_ | — |
| `IMAP_MAILBOX` | `INBOX` | — |
| `IMAP_MAX_MESSAGES` | `20` | — |

## Messaging APIs (WhatsApp / Messenger)

| Variable | Default / placeholder | Notes |
|---|---|---|
| `MESSAGING_ENABLED` | `false` | — |
| `WHATSAPP_ENABLED` | `false` | — |
| `WHATSAPP_ACCESS_TOKEN` | _(empty)_ | — |
| `WHATSAPP_PHONE_NUMBER_ID` | _(empty)_ | — |
| `WHATSAPP_VERIFY_TOKEN` | _(empty)_ | — |
| `WHATSAPP_APP_SECRET` | _(empty)_ | — |
| `MESSENGER_ENABLED` | `false` | — |
| `MESSENGER_PAGE_ACCESS_TOKEN` | _(empty)_ | — |
| `MESSENGER_VERIFY_TOKEN` | _(empty)_ | — |
| `MESSENGER_APP_SECRET` | _(empty)_ | — |
| `MESSAGING_DEFAULT_AUTO_SEND` | `false` | per-contact override lives in messaging_profiles |

## Image edits

| Variable | Default / placeholder | Notes |
|---|---|---|
| `IMAGE_PROVIDER` | `mock` | mock \| openai \| stability |
| `IMAGE_API_KEY` | _(empty)_ | — |
| `IMAGE_BASE_URL` | _(empty)_ | — |
| `IMAGE_MODEL` | _(empty)_ | — |
| `IMAGE_MAX_BYTES` | `5242880` | — |
| `IMAGE_MAX_PIXELS` | `4096000` | — |
| `IMAGE_ALLOWED_FORMATS` | `png,jpeg,webp` | — |
| `IMAGE_TIMEOUT_SECONDS` | `60` | — |
| `IMAGE_STORAGE_DIR` | `./var/images` | — |
| `IMAGE_ASSET_TTL_SECONDS` | `86400` | — |

## Jobs (worker process)

| Variable | Default / placeholder | Notes |
|---|---|---|
| `WORKER_ENABLED` | `true` | — |
| `WORKER_CONCURRENCY` | `2` | — |
| `WORKER_POLL_INTERVAL_SECONDS` | `1.0` | — |
| `JOB_TIMEOUT_SECONDS` | `300` | — |
| `JOB_MAX_ATTEMPTS` | `3` | — |
| `JOB_RETENTION_DAYS` | `14` | — |

## Audit + memory hygiene

| Variable | Default / placeholder | Notes |
|---|---|---|
| `AUDIT_RETENTION_DAYS` | `365` | — |
| `MEMORY_RETENTION_DAYS` | `180` | — |
| `MEMORY_MAX_ITEMS_PER_USER` | `500` | — |

## Operations

| Variable | Default / placeholder | Notes |
|---|---|---|
| `BACKUP_DIR` | `./var/backups` | — |
| `BACKUP_AGE_SECONDS` | `0` | seconds of pg_dump age an alert tolerates |
| `METRICS_ENABLED` | `true` | — |
| `ALERT_WEBHOOK_URL` | _(empty)_ | optional: POSTs a JSON alert on critical failures |
| `SECRET_ROTATION_DUE_DAYS` | `90` | — |

## Config-only variables (not in `.env.example`)

Defined in `app/config.py` (`Settings`) / set by Docker Compose, so they work even
though they don't appear in `.env.example`:

| Variable | Default | Notes |
|---|---|---|
| `DEV_AUTH_BYPASS` | `false` | Dev only: authenticates every request as the first admin. **Forbidden in production.** |
| `WORKER_IN_API` | `true` (app) / `false` (compose) | Run the job worker inside the API process. Compose sets `false` so the worker runs as its own service. |

## Docker Compose-only variables

Only consumed by `docker-compose.yml` / `docker-compose.prod.yml`, not by the app itself:

| Variable | Default | Notes |
|---|---|---|
| `POSTGRES_USER` | `armx` | Bundled-db profile only (unused with Supabase). |
| `POSTGRES_PASSWORD` | — | **Required** for the bundled-db profile: `${POSTGRES_PASSWORD:?…}` fails if unset. |
| `POSTGRES_DB` | `armx` | Bundled-db profile only. |
| `NGINX_HTTP_PORT` | `80` | Host port for the nginx `edge` profile. |
| `NGINX_HTTPS_PORT` | `443` | Host port for the nginx `edge` profile. |
| `MQTT_TLS_PORT` | `8883` | Host port for the Mosquitto `smarthome` profile. |
| `API_CPU_LIMIT` / `API_MEMORY_LIMIT` | — | Optional compose resource limits for the `api` service. |
| `WORKER_CPU_LIMIT` / `WORKER_MEMORY_LIMIT` | — | Optional compose resource limits for the `worker` service. |
| `TZ` | — | Container timezone. |
| `N8N_HOST` | `n8n.local` | Hostname n8n advertises (`workflows` profile). |
| `N8N_BASIC_AUTH_USER` | `admin` | n8n UI basic-auth user. |
| `N8N_BASIC_AUTH_PASSWORD` | — | **Required** for the `workflows` profile if unset compose fails. |
| `N8N_ENCRYPTION_KEY` | — | **Required** for the `workflows` profile if unset compose fails. |
| `N8N_WEBHOOK_URL` | `http://n8n:5678/` | Base URL n8n uses in webhook links. |

## Backup/restore script variables

| Variable | Notes |
|---|---|
| `BACKUP_ENCRYPTION_PASSWORD` | **Required** by `scripts/backup.sh` / `scripts/restore.sh` (`make backup`); encrypts the `pg_dump` archive. Keep it in a secrets manager, not in `.env` next to the backup. |

## Required in production

With `ENVIRONMENT=production` the app **refuses to start** (`app/config.py`) unless:

- `JWT_SECRET_KEY` is set and at least 32 characters
- `ENCRYPTION_KEY` is a valid Fernet key
- `DATABASE_URL` points at PostgreSQL/Supabase (SQLite is rejected)
- `BACKEND_CORS_ORIGINS` lists real client origins (no `*`, not empty)
- `DEMO_INSECURE=false` and `DEV_AUTH_BYPASS=false`
- Every enabled integration has its secrets, e.g. `OPENAI_API_KEY` when `LLM_PROVIDER=openai`,
  `ANTHROPIC_API_KEY` when `LLM_PROVIDER=anthropic`, SMTP settings when `EMAIL_DELIVERY_MODE=smtp`,
  `N8N_SIGNING_SECRET` + `N8N_WORKFLOWS` when `N8N_ENABLED=true`, etc.

In development/demo, a missing `JWT_SECRET_KEY` / `ENCRYPTION_KEY` is auto-generated for the
process and flagged in diagnostics — convenient locally, never acceptable in production.

## Minimal local `.env`

Nothing else is required to run locally — defaults give you SQLite + outbox email + mock LLM:

```bash
cp .env.example .env
# optionally set real values only for the features you want to exercise, e.g.:
# LLM_PROVIDER=openai
# OPENAI_API_KEY=sk-...
```
