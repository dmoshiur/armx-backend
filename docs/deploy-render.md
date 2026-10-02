# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

# Deploying A.R.M.X AI on Render + Turso + an external MQTT broker

This is the production deployment runbook for the `backend_python/` service. It targets one
Render **Web Service** (native Python runtime, `uvicorn`), all persistence in a remote
**Turso/libSQL** database, and device transport through an **external MQTT broker** that both
the ESP32 firmware and this backend connect out to. Render's filesystem is ephemeral, so the
service must never treat local disk as storage; that is why a local SQLite file is rejected by
`app/config.py` outside the `local`/`demo` profiles.

The Blueprint lives at the repository root: [`../render.yaml`](../render.yaml).

## 1. Architecture

```
Flutter app ── HTTPS / WSS ──┐
                             v
                 Render Web Service (uvicorn, single instance)
                   │    │                 ▲
   libSQL/TLS 443  │    │ MQTT/TLS 8883   │ inbound HTTP only
                   v    v                 │ (Render routes, health probes)
              Turso DB  External MQTT broker ── MQTT/TLS 8883 ── ESP32 devices
```

* The backend only ever **dials out** to the broker and the database.
* Render terminates TLS and forwards plain HTTP to the container; `uvicorn` is started with
  `--proxy-headers --forwarded-allow-ips='*'` so the app sees `https`/`wss` for public
  clients. Render's proxy is the only network hop that can reach the container port.
* Cloudinary is intentionally **not** integrated. This backend currently has no image-upload
  feature (the only upload endpoint stores intercom audio in the database). If an avatar,
  device-photo, or admin-panel image feature is added later, Cloudinary may hold those
  ordinary, non-biometric images only. Face images, face embeddings, voice samples, and any
  other biometric data must never reach Cloudinary or any other off-device service
  (AGENTS.md rule 3).

## 2. Prerequisites

* The Git repository connected to a Render account (the Blueprint is at the repo root).
* A Turso account and the Turso CLI (`turso auth login`).
* An MQTT broker reachable from the public internet, e.g. a free
  [HiveMQ Cloud Serverless](https://www.hivemq.com/mqtt-cloud-broker/) cluster (TLS-only,
  secure MQTT/TCP on `8883`, credentials from its **Access Management** tab). A self-hosted
  broker with a publicly trusted certificate also works.
* The ESP32 firmware must be pointed at the same broker host/port/credentials.

## 3. Create the Turso database

```bash
# Singapore (sin) pairs with the Render singapore region in render.yaml.
turso db create armx-backend --location sin
turso db show armx-backend --url        # -> libsql://armx-backend-<org>.turso.io
turso db tokens create armx-backend     # -> TURSO_AUTH_TOKEN (copy once)
```

Keep the database in the same region as the web service (`sin` / `singapore`). Every statement
is a network round trip, and the libSQL driver exposes no connect timeout, so a distant region
adds latency to every request and increases the chance of a stuck cold start.

`DATABASE_URL` accepts the URL printed by Turso as-is (`libsql://…`). The app normalizes it to
`sqlite+libsql://…` and applies TLS (`secure=true`). Staging/production additionally require an
explicit TLS flag, and the pasted `libsql://` form already satisfies that. **Never** append the
auth token to the URL; it belongs only in `TURSO_AUTH_TOKEN`.

## 4. Create the service from the Blueprint

1. In the Render Dashboard: **New → Blueprint**, select this repository.
2. Render reads `render.yaml` and asks for every `sync: false` value. Provide:

| Variable | Value |
| --- | --- |
| `PUBLIC_API_BASE_URL` | `https://<service-name>.onrender.com` (the URL Render shows after creation; the Blueprint names the service `armx-backend`) |
| `DATABASE_URL` | `libsql://armx-backend-<org>.turso.io` from step 3 |
| `TURSO_AUTH_TOKEN` | token from step 3 |
| `JWT_SECRET_KEY` | random, **at least 32 chars**: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `BOOTSTRAP_ADMIN_PASSWORD` | **at least 12 chars**; creates the owner on first boot |
| `CORS_ALLOWED_ORIGINS` | Flutter web origin(s), comma-separated; blank blocks all browser origins (native apps are unaffected) |
| `MQTT_HOST` | broker host, e.g. `abc123.s1.eu.hivemq.cloud` |
| `MQTT_USERNAME` / `MQTT_PASSWORD` | broker credentials (HiveMQ **Access Management**) |

    Optional (add in the dashboard, not required to boot): `LLM_PROVIDER` and
    `OLLAMA_BASE_URL` (a publicly reachable HTTPS Ollama endpoint) or
    `OPENAI_COMPATIBLE_BASE_URL` / `OPENAI_COMPATIBLE_API_KEY` /
    `OPENAI_COMPATIBLE_MODEL`. Without these, chat returns a clean "LLM unavailable" error;
    note that a local Ollama on `localhost` is **not** reachable from Render.

3. Optional local validation: `render blueprints validate render.yaml` (Render CLI), or push
   the branch and let the Blueprint sync report errors.

### Environment variables set in the Blueprint

| Variable | Purpose |
| --- | --- |
| `ENVIRONMENT=production`, `DEMO_INSECURE=false` | Enables the strict profile: HTTPS/WSS only, remote libSQL + token required, no local SQLite |
| `DATABASE_TIMEOUT_SECONDS=30` | Driver statement/connect timeout passed to libSQL |
| `DATABASE_POOL_PRE_PING=true` | Detects half-open pooled connections; one extra round trip per checkout |
| `ALLOW_PLAIN_HTTP_HEALTH_PROBE=true` | Allows **only** a parameterless `GET /health` over Render's internal plain-HTTP probe; the platform edge still redirects public HTTP to HTTPS, and every other request keeps requiring TLS |
| `MQTT_ENABLED=true`, `MQTT_PORT=8883`, `MQTT_KEEPALIVE_SECONDS=30` | External broker transport; `MQTT_TLS_CA_FILE` is intentionally unset so the system CA store validates a managed broker's certificate |
| `PYTHONUNBUFFERED=1` | Streams logs during build/start |

`PYTHON_VERSION` is not set: the repo ships `.python-version` (`3.12`) at the repository root
and in `backend_python/`, which Render resolves to the latest 3.12 patch. If you prefer the
environment variable, it must be **fully qualified** (e.g. `3.12.14`), and a value already set
in the dashboard overrides both files.

## 5. Deploy and confirm `/health`

The start command runs `alembic upgrade head` and then `uvicorn`. Free instances do not support
Render's `preDeployCommand`, so the (idempotent) migration runs at every start; on a paid plan
with more than one instance, move `alembic upgrade head` into `preDeployCommand` so a single
instance migrates per deploy.

```bash
curl --fail https://<service-name>.onrender.com/health
# {"server_version":"0.1.0","requires_pairing":true,"at":"..."}
```

Render sends `GET /health` every few seconds; it must answer `2xx`/`3xx` within 5 seconds or
the deploy is cancelled after 15 minutes (and a running instance that keeps failing is
restarted). `/health` executes `SELECT 1` against Turso, which keeps it a real readiness check.

If a deploy fails with `tls_required` on `/health` despite `ALLOW_PLAIN_HTTP_HEALTH_PROBE=true`,
check the dashboard value and the service logs; the flag is what lets the internal probe through.

## 6. Confirm the WebSocket from the real Flutter app

1. Point the Flutter client at `https://<service-name>.onrender.com` (WebSocket URL
   `wss://<service-name>.onrender.com/ws`).
2. Pair/sign in as usual, then open the chat screen and send one message. A successful
   `assistant.done` confirms the WSS upgrade, authentication, and the database round trip.
3. Keepalive: `uvicorn` pings every 20 s (`--ws-ping-interval 20`), the app sends a
   `system.heartbeat` frame every 25 s, and Render documents no fixed WebSocket timeout. Both
   are shorter than Render's 15-minute idle window, so an actively used socket stays warm.
4. Free instances spin down after 15 minutes with no inbound traffic — **including WebSocket
   messages from existing connections** — and wake on the next HTTP request or new WebSocket
   connection (~1 minute). Reconnect logic in the client should tolerate that.
5. Optional long-hold check: hold a `/ws` connection open for >5 minutes (e.g. with
   `websocat` or a small Python client passing the `Authorization` header) and confirm it is
   not dropped. This disproves the outdated claim that Render's free plan drops WebSockets
   after five minutes.

## 7. Free vs paid: which plan for demo day

Confirmed against Render's docs on 2026-10-02:

| | Free | Smallest paid instance (`0.5c-512mb`, $7/mo, always-on) |
| --- | --- | --- |
| Spin-down | After 15 min with no inbound traffic; ~1 min to wake | Never |
| Instance hours | 750/workspace/month (spun-down time does not count) | Billed monthly |
| CPU / RAM | 0.1 CPU, 512 MB | 0.5 CPU, 512 MB (`0.5c-512mb`) |
| Persistent disk | Not available (filesystem is ephemeral) | Available |
| Pre-deploy command | Not supported | Supported |
| Other | Single instance only, no shell/one-off jobs, may restart at any time, Render may suspend a free service that initiates a lot of external traffic (Turso round trips count) | — |

**Recommendation: switch the service to the smallest paid instance (`0.5c-512mb`, $7/mo) for
demo day.** `render.yaml` ships `plan: free` so the Blueprint always validates on any account;
change the plan in the dashboard (**Settings → Instance Type**) or set
`plan: 0.5c-512mb` and re-sync. One minute of cold start in front of judges is the main risk
of staying free.

If you stay on the free plan, cover it two ways:

1. **External uptime pinger** (free UptimeRobot monitor, cron-job.org, etc.) hitting
   `https://<service-name>.onrender.com/health` every ~10 minutes (well under the 15-minute
   window). Start it well before the demo — Render counts these pings as inbound traffic, so
   the service stays awake. A 750-hour month is 720 hours, so a service that never sleeps can
   exhaust Free instance hours in a long month: keep the pinger to waking hours, or accept
   brief spin-downs.
2. **Manual warm-up**: `curl https://<service-name>.onrender.com/health` and wait for the
   ~1-minute response, then open the Flutter app while the service is still warm.

Also note that Render serves a standard "disallow all" `robots.txt` while a free service is
spun down (without waking it) — harmless for the app.

## 8. MQTT architecture (ESP32 → external broker → backend)

* Render exposes only one HTTP(S)/WSS port, so it cannot host a raw MQTT listener. ESP32
  devices connect **directly** to the external broker over MQTT/TLS `8883`; the backend also
  connects **out** to that broker (`aiomqtt`, TLS, authenticated).
* Topic contract is unchanged: commands publish to `armx/{site}/{device}/cmd` (QoS 1),
  telemetry is consumed from `armx/{site}/{device}/state`.
* RiskPolicy gating is unchanged: the backend still evaluates the server-side risk policy
  before any command is published; broker acceptance is not proof of hardware actuation.
* Do **not** publish the broker port from Render or any other host; the broker is a separate
  managed/self-hosted service, ideally with per-device topic ACLs.
* Managed brokers (HiveMQ Cloud, EMQX Cloud, ...) present publicly trusted certificates, so
  leave `MQTT_TLS_CA_FILE` unset and the system CA store is used. Only a self-hosted broker
  with a private CA needs `MQTT_TLS_CA_FILE`, which is awkward on Render (ephemeral
  filesystem); prefer a publicly trusted certificate (e.g. Let's Encrypt) for that case.

## 9. Turso/libSQL notes and limits

* **Driver concurrency**: the official Python client (`libsql`) is synchronous and holds the
  GIL per call, so the async dialect in `app/db/libsql_async.py` runs every statement on a
  worker thread. Statements serialize; keep the database in-region and keep `/health` cheap.
* **No connect timeout**: an endpoint that accepts TCP but never answers can hang the driver;
  rely on Render's health checks to restart a stuck instance rather than app-level retries.
* **Migrations**: Alembic stays in charge. `migrations/env.py` uses the same engine factory as
  the app and enables `render_as_batch`, because SQLite/libSQL support only a limited set of
  `ALTER TABLE` forms. `alembic upgrade head` / `alembic check` work against libSQL;
  `alembic upgrade --sql` (offline) is not supported for batch operations that need to reflect
  a table, so generate SQL from a live database.
* **URL forms**: `libsql://<db>-<org>.turso.io` (remote), `sqlite+libsql:///./armx.db`
  (relative local file), `sqlite+libsql:////abs/path.db` (**four** slashes for an absolute local
  path). The relative form is for local development only.
* Keep `TURSO_AUTH_TOKEN` in Render's environment; rotate it in the Turso dashboard and
  redeploy if it is ever exposed. Tokens should be scoped to the database and, where offered,
  set to expire — re-create before it lapses.

## 10. Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Deploy cancelled, `/health` returns 400 `tls_required` | `ALLOW_PLAIN_HTTP_HEALTH_PROBE` missing/false; the platform's internal probe is plain HTTP |
| Start fails with `TURSO_AUTH_TOKEN is required` | Remote `DATABASE_URL` without the token, or a local SQLite URL in the `production` profile |
| Start fails with `JWT_SECRET_KEY must contain at least 32 characters` | Short/missing signing secret |
| Start fails with `BOOTSTRAP_ADMIN_PASSWORD` error | Password shorter than 12 characters |
| 503 `service_unavailable` from `/health` | Turso unreachable (URL/token/region) or the instance is stuck on a hanging driver call |
| WebSocket closes immediately (1008) | Client used `ws://` instead of `wss://`; production only accepts secure sockets |
| WebSocket drops after idle | Free-tier spin-down: reconnect logic + a pinger or a paid plan |
| Cold start takes ~1 minute | Expected on the free plan; warm up before showing the app |
