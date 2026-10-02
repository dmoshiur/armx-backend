# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

# Deploying A.R.M.X AI on Render + Turso + an external MQTT broker

This is the production deployment runbook for this repository (the whole repo **is** the
FastAPI service — `app/`, `migrations/`, `alembic.ini`, and `pyproject.toml` live at the
repository root). It targets one Render **Web Service** (native Python runtime, `uvicorn`),
all persistence in a remote **Turso/libSQL** database, and device transport through an
**external MQTT broker** that both the ESP32 firmware and this backend connect out to.
Render's filesystem is ephemeral (wiped on every redeploy, restart, and free-tier
spin-down), so the service must never treat local disk as storage; that is why a local
SQLite file is rejected by `app/config.py` outside the `local`/`demo` profiles.

The Blueprint lives at the repository root: [`../render.yaml`](../render.yaml).

> **Verification status.** Everything marked *verified* below was checked against Render's
> or Turso's own documentation and/or executed locally on 2026-10-02. The Render-side steps
> (Blueprint sync, `/health` on the real URL, `wss://…/ws` from a real client) require the
> project's Render/Turso/HiveMQ credentials and were **not** executed by the coding sandbox;
> §11 is the exact checklist to run on the real deployment before demo day.

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

* The backend only ever **dials out** to the broker and the database; Render exposes only
  its single public HTTP(S)/WSS port and never an MQTT listener.
* Render terminates TLS and forwards plain HTTP to the container; `uvicorn` is started with
  `--proxy-headers --forwarded-allow-ips='*'` so the app sees `https`/`wss` for public
  clients. Render's proxy is the only network hop that can reach the container port.
* **Cloudinary is intentionally not integrated.** This backend currently has no image-upload
  feature, so no Cloudinary keys exist and no Cloudinary SDK is installed. Face images, face
  embeddings, voice samples, and any other biometric data must never reach Cloudinary or any
  other off-device service (AGENTS.md rule 3); `tests/test_cloudinary_boundary.py` enforces
  that no module can reach an external image/object-storage SDK. If an avatar, device-photo,
  or admin-panel image feature is added later, Cloudinary may hold those ordinary,
  non-biometric images only, and the upload endpoints must require an authenticated session
  plus type/size validation. Intercom audio is deliberately excluded too: it is message
  content stored in the database and served only to opted-in recipients.

## 2. Prerequisites

* The Git repository connected to a Render account (the Blueprint is at the repo root).
* A Turso account and the Turso CLI (`turso auth login`).
* An MQTT broker reachable from the public internet. **Chosen broker: a free
  [HiveMQ Cloud Serverless](https://www.hivemq.com/mqtt-cloud-broker/) cluster** (TLS-only,
  secure MQTT/TCP on `8883`). A self-hosted Mosquitto on an always-on box with a publicly
  trusted certificate also works (§8).
* The ESP32 firmware pointed at the same broker host/port/credentials.

## 3. Create the Turso database

```bash
# Singapore (sin) pairs with the Render singapore region in render.yaml.
turso db create armx-backend --location sin
turso db show armx-backend --url        # -> libsql://armx-backend-<org>.turso.io
turso db tokens create armx-backend     # -> TURSO_AUTH_TOKEN (copy once)
```

Keep the database in the same region as the web service (`sin` / `singapore`). Every
statement is a network round trip and the libSQL driver exposes no connect timeout, so a
distant region adds latency to every request and increases the chance of a stuck cold start.

`DATABASE_URL` accepts the URL printed by Turso as-is (`libsql://…`). The app normalizes it
to `sqlite+libsql://…` and applies TLS (`secure=true`). Staging/production additionally
require an explicit TLS flag, and the `libsql://` form already satisfies that. **Never**
append the auth token to the URL; it belongs only in `TURSO_AUTH_TOKEN`.

For a purely local trial without a Turso account, the same dialect runs against a file
(`sqlite+libsql:///./armx.db`, four slashes for absolute paths). That form is rejected in
`staging`/`production` because the platform filesystem is ephemeral.

## 4. Create the service from the Blueprint

1. In the Render Dashboard: **New → Blueprint**, select this repository.
2. Render reads `render.yaml` and asks for every `sync: false` value. Provide:

| Variable | Value |
| --- | --- |
| `PUBLIC_API_BASE_URL` | `https://<service-name>.onrender.com` (the URL Render shows after creation; the Blueprint names the service `armx-backend`) |
| `DATABASE_URL` | `libsql://armx-backend-<org>.turso.io` from §3 |
| `TURSO_AUTH_TOKEN` | token from §3 |
| `JWT_SECRET_KEY` | random, **at least 32 chars**: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `BOOTSTRAP_ADMIN_PASSWORD` | **at least 12 chars**; creates the owner on first boot |
| `CORS_ALLOWED_ORIGINS` | Flutter web origin(s), comma-separated; blank blocks all browser origins (native apps are unaffected) |
| `MQTT_HOST` | broker host, e.g. `abc123.s1.eu.hivemq.cloud` |
| `MQTT_USERNAME` / `MQTT_PASSWORD` | broker credentials (HiveMQ **Access Management**) |
| `ASHNA_API_KEY` | key from <https://app.ashna.ai/account?tab=api> — **required**: startup fails loudly without it, and there is no silent fallback to another provider |

    Optional (add in the dashboard): `ASHNA_BASE_URL` / `ASHNA_MODEL` overrides, or switch
    `LLM_PROVIDER` to `openai_compatible` with `OPENAI_COMPATIBLE_BASE_URL` /
    `OPENAI_COMPATIBLE_API_KEY` / `OPENAI_COMPATIBLE_MODEL`. `LLM_PROVIDER=ollama` is **not**
    useful on Render: a local Ollama on `localhost` is not reachable from the service.
3. Validate the Blueprint before syncing (*verified*: Render CLI v2.7.0+ and the Render API
   both expose Blueprint validation; IDEs get live validation from the JSON schema at
   `https://render.com/schema/render.yaml.json`):

   ```bash
   render blueprints validate render.yaml
   ```

   A malformed field stops the Blueprint sync before anything is deployed.

### Environment variables set in the Blueprint

| Variable | Purpose |
| --- | --- |
| `ENVIRONMENT=production`, `DEMO_INSECURE=false` | Enables the strict profile: HTTPS/WSS only, remote libSQL + token required, no local SQLite, minimum-length secrets enforced |
| `DATABASE_TIMEOUT_SECONDS=30` | Driver statement/connect timeout passed to libSQL |
| `DATABASE_POOL_PRE_PING=true` | Detects half-open pooled connections; one extra round trip per checkout |
| `ALLOW_PLAIN_HTTP_HEALTH_PROBE=true` | Allows **only** a parameterless `GET /health` over Render's internal plain-HTTP probe; the platform edge still redirects public HTTP to HTTPS, and every other request keeps requiring TLS |
| `MQTT_ENABLED=true`, `MQTT_PORT=8883`, `MQTT_KEEPALIVE_SECONDS=30` | External broker transport; `MQTT_TLS_CA_FILE` is intentionally unset so the system CA store validates a managed broker's certificate |
| `LLM_PROVIDER=ashna`, `ASHNA_API_KEY` | Hosted `ashna-x1` chat provider (openai-compatible) |
| `PYTHONUNBUFFERED=1` | Streams logs during build/start |

`PYTHON_VERSION` is not set: the repo ships `.python-version` (`3.12`) at the repository
root, which Render resolves to the latest 3.12 patch (*verified*: Render reads a root
`.python-version` and allows omitting the patch version). New Render services default to a
much newer Python, so keeping this file pins the runtime the project is tested on. An
explicit `PYTHON_VERSION` env var overrides the file and must be fully qualified (e.g.
`3.12.15`).

## 5. Deploy and confirm `/health`

The start command runs `alembic upgrade head` and then `uvicorn`. Free instances do not
support Render's `preDeployCommand`, so the (idempotent) migration runs at every start; on a
paid plan with more than one instance, move `alembic upgrade head` into `preDeployCommand`
so a single instance migrates per deploy.

```bash
curl --fail https://<service-name>.onrender.com/health
# {"server_version":"0.1.0","requires_pairing":true,"at":"..."}
```

*Verified against Render's health-check docs*: Render sends `GET /health` every few seconds;
it must answer `2xx`/`3xx` within **5 seconds**, otherwise a new deploy is cancelled after
**15 minutes**, a running instance that keeps failing is temporarily removed from rotation
after 15 seconds of failures, and the instance is restarted after 60 seconds of failures.
`/health` executes `SELECT 1` against Turso, which keeps it a real readiness check.

If a deploy fails with `tls_required` on `/health` despite
`ALLOW_PLAIN_HTTP_HEALTH_PROBE=true`, check the dashboard value and the service logs; the
flag is what lets the internal plain-HTTP probe through.

## 6. Confirm the WebSocket from the real client

1. Point the Flutter client at `https://<service-name>.onrender.com` (WebSocket URL
   `wss://<service-name>.onrender.com/ws`).
2. Pair/sign in as usual, then open the chat screen and send one message. A successful
   `assistant.done` confirms the WSS upgrade, authentication, the Turso round trip, and the
   Ashna provider call path.
3. Quick terminal check with [`websocat`](https://github.com/vi/websocat)
   (add the `Authorization` header the client uses for the socket):

   ```bash
   websocat -H 'Authorization: Bearer <access-token>' wss://<service-name>.onrender.com/ws
   ```

   Always use `wss://`; Render answers plain `ws://` with a 301 and most clients then fail
   the handshake (*verified*: Render's WebSocket docs).
4. Keepalive: `uvicorn` pings every 20 s (`--ws-ping-interval 20`), the app sends a
   `system.heartbeat` frame every 25 s, and Render documents **no** fixed WebSocket timeout.
   Both keep an actively used socket healthy and detect dead peers — but they are
   server-to-client frames, so they do **not** count as the inbound traffic that keeps a free
   instance awake. A client that sits silent on an open socket can still be spun down after
   15 minutes; send a message (or run the §7 pinger) before that.
5. Optional long-hold check: hold a `/ws` connection open for more than 5 minutes and confirm
   it is not dropped. Render does not enforce a maximum WebSocket connection duration.

## 7. Free vs paid: which plan for demo day

*Confirmed against Render's docs and pricing page on 2026-10-02:*

| | Free | Smallest paid instance (`0.5c-512mb`, **$7/mo**, always-on) |
| --- | --- | --- |
| Spin-down | After **15 min** with no inbound traffic (HTTP requests **and WebSocket messages from existing connections**); **~1 min** to wake | Never |
| Instance hours | 750/workspace/month (spun-down time does not count; exhausting them suspends free services until next month) | Billed monthly |
| CPU / RAM | 0.1 CPU, 512 MB | 0.5 CPU, 512 MB (`0.5c-512mb`) |
| Persistent disk | Not available (filesystem is ephemeral) | Available |
| Pre-deploy command | Not supported | Supported |
| Other | Single instance only, no shell/one-off jobs, may restart at any time, cannot receive private-network traffic, cannot use ports 18012/18013/19099 or outbound SMTP 25/465/587; Render may suspend a free service that initiates an unusually high volume of external traffic (Turso round trips and Ashna calls count) | — |

**Recommendation: switch the service to the smallest paid instance (`0.5c-512mb`, $7/mo) for
demo day.** One minute of cold start in front of judges is the main risk of staying free, and
the same plan removes the free-tier external-traffic suspension risk. `render.yaml` ships
`plan: free` so the Blueprint always validates on any account; change the plan in the
dashboard (**Settings → Instance Type**) or set `plan: 0.5c-512mb` in the Blueprint and
re-sync.

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

**Chosen broker: HiveMQ Cloud Serverless (free tier).** Setup:

1. Create a free Serverless cluster in the HiveMQ Cloud console (choose the region closest to
   the demo — for Bangladesh/Singapore hosting, an EU or Asia-Pacific cluster keeps publish
   latency reasonable).
2. Under **Access Management**, create credentials for the backend and for the ESP32 devices
   (separate users, so a device credential can be rotated without touching the service).
3. HiveMQ Cloud only accepts TLS connections on `8883` (and WSS on `8884` for browsers);
   leave `MQTT_TLS_CA_FILE` unset so the system CA store validates the certificate.
4. Set `MQTT_HOST`, `MQTT_USERNAME`, `MQTT_PASSWORD` in Render (§4) and point the ESP32
   firmware at the same host/port/credentials.
5. Restrict each credential's topic permissions if the plan supports it: devices need
   `armx/{site}/{device}/state` (publish) and `armx/{site}/{device}/cmd` (subscribe); the
   backend needs the inverse on `armx/+/+/state` and `armx/+/+/cmd`.

A self-hosted Mosquitto on an always-on home/VPS box with a publicly trusted certificate
(Lets Encrypt) also works; only that case needs `MQTT_TLS_CA_FILE`, which is awkward on
Render's ephemeral filesystem — prefer a publicly trusted certificate.

* Render exposes only one HTTP(S)/WSS port, so it cannot host a raw MQTT listener. ESP32
  devices connect **directly** to the external broker over MQTT/TLS `8883`; the backend also
  connects **out** to that broker (`aiomqtt`, TLS, authenticated, automatic reconnect with a
  3-second backoff in `app/devices/state_listener.py`).
* Topic contract is unchanged: commands publish to `armx/{site}/{device}/cmd` (QoS 1),
  telemetry is consumed from `armx/{site}/{device}/state`.
* RiskPolicy gating is unchanged: the backend still evaluates the server-side risk policy
  before any command is published; broker acceptance is not proof of hardware actuation.
* Do **not** publish the broker port from Render or any other host.
* The repository's `docker-compose.yml` still runs a local Mosquitto for the offline demo
  fallback; that broker is intentionally demo-only (self-signed TLS, anonymous clients,
  isolated Compose network) and must never be exposed.

## 9. Turso/libSQL notes and limits

* **Driver concurrency (*verified*: Turso's Python docs).** The official `libsql` client is a
  synchronous DB-API driver, and the officially documented SQLAlchemy dialect
  (`sqlalchemy-libsql`) is synchronous-only — its examples use `create_engine`, not
  `create_async_engine`. There is no true async libSQL engine. The app therefore uses the
  vendored asyncio dialect in `app/db/libsql_async.py`, which runs every blocking driver call
  on one dedicated worker thread per connection (same architecture as `aiosqlite`). The
  driver also holds the GIL for the whole call, so statements serialize with the event loop;
  keep the database in-region and keep `/health` cheap. This is the main throughput caveat
  for WebSocket chat. Turso's newer `pyturso` / `turso_serverless` packages were reviewed and
  are not drop-in SQLAlchemy async replacements; see the module docstring for detail.
* **No connect timeout**: an endpoint that accepts TCP but never answers can hang the driver;
  rely on Render's health checks to restart a stuck instance rather than app-level retries.
* **Migrations**: Alembic stays in charge. `migrations/env.py` uses the same engine factory as
  the app and enables `render_as_batch`, because SQLite/libSQL support only a limited set of
  `ALTER TABLE` forms. *Verified locally on 2026-10-02*: `alembic upgrade head` and
  `alembic check` both work against a `sqlite+libsql` file database, creating all 17 tables
  with no autogenerate diff. `alembic upgrade --sql` (offline) is not supported for batch
  operations that need to reflect a table, so generate SQL from a live database.
* Because `Settings` validates the full profile, running Alembic locally or in CI requires
  either a real `ASHNA_API_KEY` or an explicit `LLM_PROVIDER=ollama` override; the Render
  start command has the real key from the environment.
* **URL forms**: `libsql://<db>-<org>.turso.io` (remote), `sqlite+libsql:///./armx.db`
  (relative local file), `sqlite+libsql:////abs/path.db` (**four** slashes for an absolute local
  path). The relative form is for local development only.
* Keep `TURSO_AUTH_TOKEN` in Render's environment; rotate it in the Turso dashboard and
  redeploy if it is ever exposed. Tokens should be scoped to the database and, where offered,
  set to expire — re-create before it lapses.
* Pair the Turso database with the Render region (`sin` ↔ `singapore`). Render supports
  Oregon, Ohio, Virginia, Frankfurt, and Singapore; free instances are not restricted by the
  regions doc, but if a workspace refuses the combination, move **both** the database and the
  service to another region — Render does not support changing a service's region in place.

## 10. Deployed profile checklist

Outside the explicit local/demo profile:

- `ENVIRONMENT=production`, `DEMO_INSECURE=false`, HTTPS/WSS through the platform's TLS
  terminator (`--proxy-headers --forwarded-allow-ips='*'` on Render). `ALLOW_PLAIN_HTTP_HEALTH_PROBE=true`
  excepts only a parameterless `GET /health`; every other request still requires TLS.
- `PUBLIC_API_BASE_URL` set to the public HTTPS origin, remote `DATABASE_URL` + token,
  persistent random `JWT_SECRET_KEY` (≥32 chars), owner password ≥12 chars, all secrets in
  Render's environment variables (never in the repo).
- External (or at minimum non-anonymous, TLS) MQTT with real credentials; per-device topic
  ACLs where the broker supports them. Per-device MQTT attestation and command
  acknowledgements are not defined by the current contract; do not treat broker telemetry as
  proof of physical execution.
- `LLM_PROVIDER=ashna` with a real `ASHNA_API_KEY`; the key is redacted from logs. If the key
  is missing the service refuses to start — it never silently falls back.
- No state on local disk. Anything that looks like persistence (SQLite files, uploaded
  images, cached tokens) must live in Turso or another managed store; the filesystem is wiped
  on redeploy, restart, and spin-down.
- Migrations applied as a controlled step (`alembic upgrade head`), with backups, logging,
  network policy, and retention reviewed before exposing user data. Never point preview
  environments at the production database (`previews.generation: off` in `render.yaml`).

## 11. Pre-demo verification checklist (run on the real deployment)

```bash
# 1. Readiness (also warms a spun-down free instance).
curl --fail --max-time 120 https://<service-name>.onrender.com/health

# 2. An authenticated route must reject anonymous callers (expect 401 + the standard envelope).
curl -s -w '\n%{http_code}\n' https://<service-name>.onrender.com/devices

# 3. WebSocket upgrade over TLS (use a real access token).
websocat -H 'Authorization: Bearer <access-token>' wss://<service-name>.onrender.com/ws
#    -> expect a connected socket; send {"type":"chat.send","text":"hello"} and watch for
#       assistant.token / assistant.done frames.

# 4. One real Ashna-backed chat round trip from the Flutter client (proves DB + LLM + WSS).
```

Record the date, service URL, and observed results here before demo day:

| Check | Result |
| --- | --- |
| `/health` returned `{"server_version":"0.1.0",...}` | ☐ |
| WebSocket `wss://…/ws` connected and returned `assistant.done` | ☐ |
| One device command reached the external broker and the state round-trip appeared on `/ws` | ☐ |
| Kill-switch engaged and re-enabled explicitly from the admin UI | ☐ |

## 12. Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Blueprint sync fails mentioning `rootDir` or the build cannot find `pyproject.toml` | A stale `rootDir: backend_python` was restored; the repo is flat — remove it |
| Deploy cancelled, `/health` returns 400 `tls_required` | `ALLOW_PLAIN_HTTP_HEALTH_PROBE` missing/false; the platform's internal probe is plain HTTP |
| Start fails with `ASHNA_API_KEY is required when LLM_PROVIDER=ashna` | Blueprint prompt left empty, or a non-Ashna provider was intended; set the key or switch `LLM_PROVIDER` |
| Start fails with `TURSO_AUTH_TOKEN is required` | Remote `DATABASE_URL` without the token, or a local SQLite URL in the `production` profile |
| Start fails with `JWT_SECRET_KEY must contain at least 32 characters` | Short/missing signing secret |
| Start fails with `BOOTSTRAP_ADMIN_PASSWORD` error | Password shorter than 12 characters |
| 503 `service_unavailable` from `/health` | Turso unreachable (URL/token/region) or the instance is stuck on a hanging driver call |
| WebSocket closes immediately (1008) | Client used `ws://` instead of `wss://`; production only accepts secure sockets |
| WebSocket drops after idle | Free-tier spin-down: reconnect logic + client traffic, a `/health` pinger, or a paid plan |
| Cold start takes ~1 minute | Expected on the free plan; warm up before showing the app |
| Chat answers with "assistant service unavailable" | Ashna key invalid/expired or rate-limited; check Render logs (the key itself is redacted) |
