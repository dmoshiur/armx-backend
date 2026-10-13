# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

# Build report

Phase-by-phase record of what was built, how to run it, how to test it, what still needs manual
setup, and exactly what remains mocked. Written as each phase lands so the state of the system is
never inferred from the code alone.

Legend: **Run** = how to exercise it locally · **Test** = the automated evidence · **Mocked** =
what is deliberately not real yet.

---

## Phase 1 — Repo skeleton, Docker, typed settings, `/health`, CI

**Built**

| Area | Files |
|---|---|
| Settings | `app/config.py`, `app/core/ratelimit_spec.py`, `app/integrations/specs.py` |
| Primitives | `app/core/{errors,logging,redaction,crypto,passwords,risk,time,enums,metrics,alerts,privacy}.py` |
| HTTP | `app/main.py`, `app/api/{middleware,deps,routes_health}.py` |
| Ops | `Dockerfile`, `docker-compose.yml`, `docker-compose.prod.yml`, `deploy/nginx.conf`, `deploy/proxy_params.inc`, `mosquitto/mosquitto.conf`, `mosquitto/acl`, `scripts/{entrypoint.sh,backup.sh,restore.sh,secret_scan.py}`, `Makefile`, `.env.example` |
| CI | `.github/workflows/ci.yml` |

Highlights

* **Production guard.** `ENVIRONMENT=production` refuses to boot when `DEMO_INSECURE=true`,
  `JWT_SECRET_KEY` is missing/short/a placeholder, `ENCRYPTION_KEY` is missing, the database is
  SQLite, CORS origins are empty or `*`, or an enabled integration is missing its credentials
  (MQTT without TLS/credentials/CA, GitHub without exactly one allowlisted repo, WhatsApp without
  its app secret, n8n without a signing secret, and so on). Development generates ephemeral
  secrets and warns loudly on every boot.
* **Boot-time validation of policy inputs.** Every rate-limit string and every allowlist
  (`KILL_SWITCH_ALLOWED_TOOLS`, `N8N_WORKFLOWS`, `MCP_SERVERS`) is parsed at startup, so a typo
  cannot silently disable a limit. A HIGH-risk n8n workflow that does not declare `confirm=true`
  fails the boot.
* **Middleware order is deliberate:** body-size guard → request/trace context → TLS enforcement →
  security headers (attached to error responses too).
* **Health surface:** `/health` (liveness, 503 when the database is unreachable), `/ready`
  (fails until migrations are applied — this is what a load balancer should poll), `/metrics`
  (Prometheus text; unauthenticated only in local development, admin-only elsewhere).
* **Logging** is structured JSON or console, always through a redaction filter that strips
  credential-shaped values and key-value pairs.
* **Backups** are encrypted (`pg_dump -Fc` → AES-256-CBC/PBKDF2), checksummed, verified by
  decrypting and header-checking, and pruned; `scripts/restore.sh` verifies the checksum, refuses
  to restore over a non-empty database unless forced, and documents the drill in
  `docs/operations.md`.

**Run**

```bash
cp .env.example .env
make venv && make install && make migrate && make api
curl -fsS localhost:8000/health && curl -fsS localhost:8000/ready
make prod-check            # validates a production .env without starting the app
```

**Test** — `make verify` → formatter, linter, strict `mypy`, secret scan, `pytest`
(`tests/test_config.py`, `tests/test_health.py`, `tests/test_secret_scan.py`).

**Manual setup still required**

* Real deployment secrets (`JWT_SECRET_KEY`, `ENCRYPTION_KEY`, database credentials) and TLS
  certificates for nginx (Certbot in `deploy/nginx.conf`).
* A `BACKUP_ENCRYPTION_PASSWORD` in the platform's secret store before scheduling `backup.sh`.

**Mocked** — nothing in this phase. No integration is contacted at this point.

---

## Phase 2 — Data model and migrations

**Built** — `app/db/{base,sql,models,urls,session,bootstrap}.py`, `migrations/` (env, template,
revision `0001`), `tests/test_migrations.py`, `tests/test_postgres_dialect.py`.

28 tables: `users`, `sessions`, `refresh_tokens`, `email_tokens`, `devices`, `device_keys`,
`linked_devices`, `device_unlink_events`, `pairing_sessions`, `registry_snapshots`,
`tool_definitions`, `tool_permissions`, `approvals`, `audit_events`, `integration_connections`,
`memory_items`, `automation_rules`, `rule_execution_history`, `guest_consents`,
`messaging_profiles`, `messaging_inbound_events`, `system_flags`, `rate_limit_counters`, `jobs`,
`mail_outbox`, `used_nonces`, `image_assets`, `site_builds`.

Design decisions worth reviewing:

* **Nothing secret is stored in a readable form.** Passwords are argon2id; refresh tokens,
  pairing keys and pairing codes are hashes; device owner passwords are hashes scoped to a single
  link row; `integration_connections.secret_ref` holds an environment-variable *name* (validated to
  look like one); memory content is encrypted. A test asserts no column is named
  `password`/`token`/`secret`/`api_key`.
* **Dialect independence.** `UtcDateTime` returns aware UTC on every dialect (SQLite drops the
  offset otherwise, which is where naive/aware `TypeError`s come from); `EnumStr` stores the
  member's value as text so `IntEnum` risk tiers and `StrEnum` statuses round-trip identically and
  a new enum member needs no type migration. Alembic renders both as plain SQL through
  `render_item`, so historical revisions never import application code.
* **Constraints that encode policy:** a partial unique index allows a device to be actively linked
  to only one account; `used_nonces.nonce_hash` is unique so replay protection is a constraint
  rather than a code path; `jobs.idempotency_key` is unique so a retried request cannot produce a
  second deploy.
* **Retention is enforced, not aspirational:** `app/jobs/maintenance.py` deletes audit events,
  jobs, memory items, outbox mail and expired assets past their configured windows, and requeues
  jobs whose worker lease expired.
* **Alembic runs before the API accepts traffic** (`scripts/entrypoint.sh`), and `/ready` refuses
  traffic against an unmigrated schema.

**Run**

```bash
make migrate                       # SQLite by default
make revision m="describe change"  # autogenerate, then review
```

**Test** — `tests/test_migrations.py` applies every revision to a fresh database, asserts the table
set and recorded revision, and runs Alembic's own comparator to fail on any model/migration drift.
`tests/test_postgres_dialect.py` (CI job `test-postgres`) proves JSONB queries, `timestamptz`
round-tripping, enum storage as text, and concurrent `SELECT … FOR UPDATE SKIP LOCKED` claims on a
real PostgreSQL 16 service.

**Manual setup still required** — a Supabase connection string in `DATABASE_URL` for production
(transaction pooler `:6543` is detected and disables server-side prepared statements
automatically).

**Mocked** — nothing in this phase.

---

## Phase 3 — Authentication, sessions and user administration

**Built**

| Area | Files |
|---|---|
| Tokens | `app/auth/tokens.py` (HS256 access JWT ≤15 min, opaque refresh tokens stored only as a hash, rotation, reuse detection) |
| Scopes | `app/auth/scopes.py` (`ROLE_SCOPES` bundles, `has_scope` / `*` handling) |
| Account lifecycle | `app/auth/service.py`, `app/auth/schemas.py`, `app/auth/routes.py` (`/auth/*`) |
| Google sign-in | `app/auth/google.py` (`/auth/google/start`, `/auth/google/callback`) |
| Principal + guards | `app/auth/dependencies.py` (`current_principal`, `require_admin`, `require_scope`) |
| Administration | `app/users/routes.py` (`/admin/users*`) |
| Mail | `app/notifications/mailer.py`, `app/notifications/templates.py`, `mail_outbox` fan-out via the job queue |
| CLI | `app/cli/create_admin.py` |

**Endpoints** — `POST /auth/signup`, `/auth/login`, `/auth/refresh`, `/auth/logout`,
`/auth/verify-email`, `/auth/resend-verification`, `/auth/forgot-password`, `/auth/reset-password`,
`GET /auth/me`, `GET|DELETE /auth/sessions[/{id}]`, `GET /auth/google/start`, `POST
/auth/google/callback`; `GET|POST /admin/users`, `GET|PATCH /admin/users/{id}`, `POST
/admin/users/{id}/unlock|verification`, `GET|DELETE /admin/users/{id}/sessions`.
The first Admin is created only through `python -m app.cli.create_admin` (or `make create-admin`).

**Security properties**

* A token carries the *role it had when it was minted* but scopes are recomputed from the stored
  role on every request, so a demotion takes effect on the next call. Disabling an account bumps
  `session_epoch`, which invalidates every access token it holds; a role change does not.
* Refresh tokens are rotated on every use. Reusing a spent one revokes the whole session, writes an
  `auth.token_reuse` audit row and forces a fresh sign-in.
* Signup, password reset and verification resend answer identically whether or not the address
  exists; the delivered link carries a single-use hashed token that expires.
* Lockout after `AUTH_MAX_FAILED_LOGINS` failures for `AUTH_LOCKOUT_SECONDS`, layered under the
  per-address rate limit; a successful sign-in clears the counter.
* Passwords are argon2id, checked against a length policy and a common-password list. No response
  ever contains a hash, a token, a Google subject or another account's data.
* An administrator cannot demote or disable the last active Admin, and cannot read or reset another
  account's password - only trigger the same email flow the user would use.

**Test** — 29 tests in `tests/test_auth.py` cover enumeration resistance, lockout, rotation, token
reuse, forged and expired tokens, expired verification links, role escalation attempts and the whole
admin surface. Suite total after this phase: 118 passing, 6 skipped.

**Mocked** — email delivery (`EMAIL_DELIVERY_MODE=outbox` writes to `mail_outbox`; nothing leaves the
process). Google sign-in is implemented and unit-tested against a stubbed JWKS/HTTP layer; a real
client id/secret is still needed to use it.

**Manual setup still required** — set `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` to enable Google
sign-in; run `python -m app.cli.create_admin` for the first administrator.

---

## Phase 4 — Security Gateway, tool execution, LLM harness and the assistant

**Built**

| Area | Files |
|---|---|
| Risk model | `app/core/risk.py` (`Risk`, `requires_approval(risk, confirm=...)`) |
| Gateway | `app/security/gateway.py` - the single choke point for every tool call |
| Approvals | `app/security/approvals.py`, `app/approvals/{schemas,routes}.py` |
| Kill-switch | `app/security/kill_switch.py`, `app/admin/routes.py` |
| Rate limits | `app/security/ratelimit.py` (PostgreSQL fixed windows - no Redis) |
| Providers | `app/llm/{base,mock,openai_compatible,anthropic,ollama,factory}.py` |
| Harness | `app/harness/prompts.py`, `app/harness/runner.py` |
| Assistant | `app/assistant/schemas.py`, `app/assistant/routes.py`, `app/assistant/ws.py` |
| Tool API | `app/tools/routes.py`, `app/registry/schemas.py` |
| Audit read API | `app/audit/routes.py` |
| Wiring | `app/api/deps.py` (`app_gateway`, `app_llm`, `actor_for`), `app/main.py` (registry mirror + feature routers) |

**Endpoints** — `GET /tools`, `POST /tools/{name}/invoke`, `GET|PATCH /admin/tools[/{name}]`,
`GET /approvals`, `GET /approvals/{id}`, `POST /approvals/{id}/confirm|deny`, `GET /audit`,
`GET /admin/audit`, `GET /admin/audit/trace/{trace_id}`, `GET /admin/kill-switch`,
`POST /admin/kill-switch/engage|disengage`, `POST /assistant/message`, and the WebSocket
`/assistant/stream`.

**The one rule that makes the rest true** — the model is an untrusted planner. It receives a
catalogue and can ask for a tool by name with arguments; nothing else. `SecurityGateway.invoke` is
the only code path that runs a tool handler, and it decides in this order:

1. **Kill-switch** — engaged means only `KILL_SWITCH_ALLOWED_TOOLS` (default `health_status`) runs.
2. **Exists and enabled** — unknown names and operator-disabled tools are refused.
3. **Permission overrides** — user-level beats role-level beats global.
4. **Scopes** — taken from the stored role, recomputed per call.
5. **Argument validation** — the tool's pydantic schema, before anything else sees the data.
6. **Rate limits** — `tool:{name}:{actor}:{device}` then a global per-actor budget.
7. **Dry run** — a tool that supports it runs read-only; one that does not is refused outright.
8. **Approval** — HIGH (and MEDIUM tools that declare `confirm=True`) need a fresh, hash-bound,
   single-use, expiring approval. The approval is spent *immediately before* execution, so a call
   refused for any other reason never costs the user their approval, and a changed argument is
   refused rather than silently executed.

Every one of those outcomes - including denials and dry runs - writes exactly one audit row with the
actor, device, tool, version, risk tier, canonical argument hash, redacted arguments, outcome, error
code, duration and trace id. Audit rows are append-only; there is no update or delete endpoint.

**Harness** — `run_turn` builds a fresh system prompt and transcript per turn (client history may
only contain `user`/`assistant` turns, so a client cannot inject instructions), offers only the tools
the caller may actually use, runs each request through the gateway, and fences tool output as
`<untrusted_data>` with control characters stripped and the length capped. It is bounded by model
turns, tool calls, per-tool timeout and a wall-clock deadline, and it reports which bound it hit. A
denial is final: the prompt tells the model never to retry or rephrase a refused action.

**Providers** — `mock` (offline default), `openai`, `anthropic`, `ollama`, `openai_compatible`. All
adapters translate to one internal shape (`text`, `tool_calls`, `usage`) and raise exactly two
errors: `LLMError` for a provider-side rejection and `LLMUnavailable` for a transport, timeout or 5xx
failure. Response bodies are never echoed to a client.

**Test** — 115 new tests this phase:

| File | Tests | What it proves |
|---|---|---|
| `tests/test_gateway.py` | 23 | every branch of the authorization order, that a refusal never reaches a handler, and that an approval is bound to one actor, device and argument hash |
| `tests/test_approvals_api.py` | 9 | request → prompt → decision → execution, argument changes, expiry, isolation between accounts |
| `tests/test_tools_api.py` | 16 | the REST surface returns the same decisions as the gateway, with structured 403/404/409/422 answers |
| `tests/test_harness.py` | 17 | the loop, tool budgets, deadline, refusals, untrusted-content fencing, provider failure |
| `tests/test_llm.py` | 32 | all five adapters against stubbed transports, including 400/429/500, timeouts, malformed bodies |
| `tests/test_ratelimit.py` | 13 | per-key budgets, headers, hashed keys, window rollover, shared counters, lockout layering |
| `tests/test_assistant_api.py` | 15 | the assistant over REST and WebSocket, kill-switch behaviour, history injection rejected |

Two defects were found and fixed by these tests rather than in production: the kill-switch endpoints
were not Admin-gated, and the registry was never mirrored into the database (so the operator toggle
had nothing to change and `/admin/tools` answered 503).

**Run**

```bash
make run                                   # mock planner, SQLite, outbox mail
curl -s localhost:8000/tools -H "Authorization: Bearer $TOKEN"
curl -s localhost:8000/assistant/message -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' -d '{"text":"how are you?"}'
websocat "ws://localhost:8000/assistant/stream?token=$TOKEN"
```

**Assumptions** — `LLM_PROVIDER=mock` remains the default; the tool catalogue ships only with
`health_status` enabled and `mock_echo` disabled; `WORKER_IN_API=true` so one container is enough
locally; the kill-switch allowlist defaults to health checks.

**Lint / type / test** — `ruff format` and `ruff check` clean over `app tests scripts migrations`;
`mypy app` in strict mode clean over 84 source files (the only relaxation is `import-not-found` for
`app/main.py`, which imports the routers of phases 5-11 that do not exist yet); 244 tests collected,
**238 passing, 6 skipped** (skips require PostgreSQL or optional extras); `scripts/secret_scan.py`
clean over 134 files. The full loop is `make verify`.

**Mocked** — every integration is still off: `health_status` is the only enabled tool, `mock_echo`
exists to prove the enable/disable path, and the model provider defaults to the offline mock. No
smart-home, mail, messaging, GitHub/Vercel, n8n or MCP call is made anywhere.

**Manual setup still required** — set `LLM_PROVIDER` and the matching key/model to talk to a real
model; `OPENAI_API_KEY` (or the provider equivalent) is validated at boot only for the provider you
select.

---

## Phase 5 onwards

Phases 5–11 (linked devices, smart home, website builder, n8n/MCP/messaging, image + guest, admin
console hardening) are recorded below as they land. Nothing in phases 5+ is enabled by default, and
no integration is switched on until its phase's acceptance checks pass.