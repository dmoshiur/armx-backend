# A.R.M.X AI — Backend

**Automated Resource Management eXtension.** A tool-driven assistant platform: a Flutter/web
client talks to a FastAPI backend, which consults an LLM as an *untrusted planner* and executes
only the tool calls that the server-side **Security Gateway** authorizes.

Owner: Md. Moshiur Rahman Mohi · Brand: THAMJJ13.TOP

---

## The one rule that shapes everything

> **The model proposes. The backend decides. Every decision is audited.**

The LLM never holds a secret, never touches the database, never executes a shell command, and
never decides a risk tier, a rate limit, or whether an approval is required. It may only ask for
a *named tool* with arguments validated against a registered schema — and then the Security
Gateway checks the kill-switch, tool enablement, scopes, role, rate limit, and (for MEDIUM/HIGH
actions) a fresh, hash-bound, single-use approval before anything runs.

```
Flutter / Web client
        | HTTPS + WSS, short-lived JWT (<= 15 min, rotating refresh tokens)
        v
nginx  (TLS termination, WebSocket pass-through, edge rate limit)
        v
FastAPI (api)                                    worker (same image)
  auth/ users/ devices/ approvals/ audit/         durable DB-backed job queue
  assistant/ (harness + WS) admin/ memory/        deploy / n8n / image edits
  registry/ (tool manifests) security/ (gateway)
        v
Supabase PostgreSQL  ·  MQTT/TLS broker (ESP32)  ·  Home Assistant  ·  n8n  ·  GitHub/Vercel
```

## Quick start

### 1. Local, no external services (fastest)

```bash
cp .env.example .env                 # every value is a placeholder
make venv && make install            # Python 3.12 preferred (3.11 minimum)
make migrate                         # SQLite file in ./data
make create-admin email=owner@example.com
make api                             # http://localhost:8000  (docs at /docs in dev only)
```

With `LLM_PROVIDER=mock` the assistant answers deterministically and needs no API key; email is
recorded in the `mail_outbox` table instead of being sent (`GET /admin/mail`), and the worker
runs inside the API process. Nothing leaves the machine.

### 2. Docker, full stack

```bash
cp .env.example .env
# set at minimum: JWT_SECRET_KEY, ENCRYPTION_KEY, POSTGRES_PASSWORD, N8N_* secrets
docker compose --env-file .env --profile bundled-db up -d --build
docker compose exec api python -m app.cli.create_admin --email owner@example.com
```

Profiles: `bundled-db` (local PostgreSQL), `edge` (nginx + TLS), `smarthome` (Mosquitto + Home
Assistant), `workflows` (n8n). Production uses Supabase instead of the bundled database:

```bash
# .env.prod
DATABASE_URL=postgresql+psycopg://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres  # secret-scan:allow (documented placeholder, not a credential)
ENVIRONMENT=production
DEMO_INSECURE=false
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env.prod up -d
```

The API refuses to boot when `ENVIRONMENT=production` and a required secret is missing, still a
placeholder, or pointed at SQLite — see `app/config.py` and `make prod-check`.

## Layout

| Path | What lives there |
|---|---|
| `app/main.py` | ASGI app: middleware, error envelope, health, lifespan |
| `app/config.py` | typed settings; production guard rails |
| `app/registry/` | tool manifests, discovery, schema validation, DB mirror + snapshots |
| `app/security/` | kill-switch, risk engine, approval protocol, rate limiting, gateway |
| `app/harness/` | bounded tool-call loop, context building, untrusted-data handling |
| `app/llm/` | provider-agnostic adapters (OpenAI, Anthropic, Ollama, mock) |
| `app/tools/` | one module per capability (the plugin system) |
| `app/auth/`, `app/users/` | signup, login, refresh rotation, Google OAuth, password reset |
| `app/devices/` | linked devices, pairing, owner-password unlink, device registry |
| `app/approvals/`, `app/audit/`, `app/admin/` | approval protocol, audit trail, admin surface |
| `app/integrations/` | Home Assistant/MQTT, GitHub/Vercel, n8n, MCP, search, IMAP, WhatsApp/Messenger, image providers, SMTP |
| `app/jobs/` | durable job queue, worker loop, maintenance |
| `app/db/` | models, engine/session, URL handling, bootstrap |
| `migrations/` | Alembic; `docs/operations.md` documents the backup/restore drill |
| `scripts/` | `entrypoint.sh`, `backup.sh`, `restore.sh`, `secret_scan.py` |
| `tests/` | unit, integration, security and reliability suites |

## Commands

```bash
make verify          # formatter + linter + strict types + secret scan + tests (what CI runs)
make test            # pytest
make test-cov        # pytest with coverage
make lint typecheck  # ruff / mypy (strict)
make revision m="add device pairing index"
make create-admin email=owner@example.com
make backup          # encrypted pg_dump (requires BACKUP_ENCRYPTION_PASSWORD)
make prod-check      # validate a production .env without starting the app
```

## Security model in one page

* **Risk tiers are server-side.** LOW runs directly; MEDIUM and HIGH require a *fresh, exact-action
  approval* bound to `sha256(canonical JSON of tool + version + arguments + actor + device +
  session + nonce + expiry)`. Change one argument and the approval no longer matches.
* **Approvals are single-use and expiring.** Consumption is an atomic compare-and-set, so a
  replayed approval fails rather than executing twice.
* **The kill-switch is unconditional.** It is read from the database on *every* tool call and job
  claim, is independent of the LLM and of any biometric check, cancels in-flight work, and can only
  be released by its own explicit endpoint.
* **Tool output is data, never instructions.** Web/email/MCP/repository content is returned with
  `untrusted=True`, wrapped in data-only delimiters, and can never alter policy, risk tier or
  permissions.
* **Credentials are hashed or referenced, never stored.** argon2id passwords, hashed refresh
  tokens and pairing keys, encrypted memory content, and `integration_connections.secret_ref`
  holding an environment-variable *name* rather than a value.
* **Every tool call writes one audit row** — actor, device, session, tool version, canonical
  argument hash, risk tier, outcome, error code, trace id, registry snapshot — including denied
  and dry-run attempts.
* **Defence in depth on inputs:** canonical-JSON argument validation, per-actor and per-IP rate
  limits, lockout after repeated failures, SSRF/path-traversal guards on every outbound fetch,
  destination allowlists for deploys, and webhook signature verification.

Full detail, threat model and the deliberate non-features: [`docs/security.md`](docs/security.md).

## Build phases

The backend was built in the eleven phases described in the project prompt. Each phase is
reported in [`docs/build-report.md`](docs/build-report.md) with the files it touched, the
endpoints it added, its test results, the manual setup it still needs, and exactly what remains
mocked.

| Phase | Scope | Status |
|---|---|---|
| 1 | Skeleton, Docker, typed settings, `/health`, CI | reported |
| 2 | Data model + migrations | reported |
| 3 | Auth: signup, login, JWT/refresh, reset, OAuth, admin CLI | reported |
| 4 | Harness, LLM adapter, registry, audit, tool toggles, kill-switch | reported |
| 5 | Security Gateway: risk, approvals, rate limiting | reported |
| 6 | Linked devices: pairing, owner-password unlink, audit | reported |
| 7 | Smart home: Home Assistant + MQTT/TLS/ACL | reported |
| 8 | Web builder: sandbox, GitHub, Vercel, deploy confirmation | reported |
| 9 | n8n, MCP, WhatsApp/Messenger adapters | reported |
| 10 | Image adapter, guest greeter, admin dashboard APIs | reported |
| 11 | Hardening: security suite, backup drill, monitoring, rotation | reported |

## Testing

```bash
make verify
```

* Unit: settings validation, risk rules, registry manifests, password hashing, approval hashing
  and expiry, rate-limit windows, secret scanning.
* Integration: migrations (including a model/migration drift check), auth flows, audit
  persistence, the mock LLM adapter, and every integration adapter behind a mocked transport.
* Security: IDOR, broken access control, approval replay, prompt injection through tool output,
  SSRF, path traversal, secret leakage in logs and errors, webhook forgery.
* Reliability: timeouts, retries, provider outages, partial failures, cancellation, duplicate
  events.

CI additionally applies migrations to a real PostgreSQL 16 service and runs the dialect-specific
tests, so SQLite-only behaviour cannot slip into production.

## Licence

Proprietary. © 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. All rights reserved.
