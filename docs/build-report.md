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

## Phase 3 onwards

Phases 3–11 (auth, harness/gateway, linked devices, smart home, web builder, n8n/MCP/messaging,
image/guest/admin, hardening) are recorded below as they land.
