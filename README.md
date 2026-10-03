# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

# armx-backend

A.R.M.X AI (Automated Resource Management eXtension) — Python 3.12 / FastAPI backend for the
Flutter client in [`dmoshiur/armx`](https://github.com/dmoshiur/armx). It includes async
SQLAlchemy persistence on Turso/libSQL, Alembic migrations, paired-device authentication,
server-side signed risk verification, admin controls, audit, WebSocket chat/tool proposals,
consent-gated intercom, activity-rule storage and dry runs, and TLS-only MQTT
telemetry/command publishing.

Deployment runs on **[Render](https://render.com)** with **[Turso](https://turso.tech)** for
persistence and an external MQTT broker for device transport. Setup, local/demo operation,
operator provisioning, and development checks are documented below; the deployment runbook is
in [`docs/deploy-render.md`](docs/deploy-render.md). The published Flutter contract at
`dmoshiur/armx/docs/api.md` is authoritative; known additions and ambiguities are tracked in
[`API_GAPS.md`](API_GAPS.md), not silently treated as contract guarantees.

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
                                        (HiveMQ Cloud Serverless; Render exposes no MQTT port)

Cloudinary: reserved for ordinary, non-biometric images only. Not integrated today, because
the backend has no image-upload feature; face images, face embeddings, and voice samples must
never leave the device (AGENTS.md rule 3).
```

* **Render** runs one Web Service with `render.yaml` as infrastructure-as-code: Python 3.12
  pinned by `.python-version`, `alembic upgrade head` on start, `healthCheckPath: /health`,
  and secrets declared `sync: false`. The filesystem is ephemeral, so no persistence depends
  on local disk — the database is remote Turso.
* **Turso/libSQL** is the single database for users, devices, pairing, audit logs, intercom
  opt-in/log, activity rules, and MCP tool toggles. The URL and auth token come from
  environment variables only; tokens never appear in URLs or logs. Alembic manages the schema
  against the SQLite-compatible dialect (batch mode for `ALTER TABLE` limits).
* **MQTT** runs off-host: ESP32 devices publish/subscribe to an external broker over MQTT/TLS
  8883, and the backend connects outbound to the same broker. The topic contract
  (`armx/{site}/{device}/cmd`, `armx/{site}/{device}/state`) and the server-side RiskPolicy
  gating are unchanged.
* **Cloudinary** is not wired up (no image-upload feature exists). When one arrives
  (avatar/device photos/admin assets), it may hold only ordinary images — never biometric
  data — and uploads must require an authenticated session plus type/size validation.
  `tests/test_cloudinary_boundary.py` enforces that no module can reach an external
  image-storage SDK today; intercom audio is message content served only to opted-in
  recipients and is likewise never sent to Cloudinary or the LLM.

See [`docs/deploy-render.md`](docs/deploy-render.md) for the deployment runbook (Turso
database, Render env vars, HiveMQ Cloud broker, first deploy, WebSocket verification, and the
free-vs-paid tier decision).

## LLM provider (Groq)

The default hosted provider is Groq's `qwen/qwen3.8-27b` model. Groq serves an OpenAI-compatible Chat Completions endpoint, so the existing router and tool approval flow are reused. Groq deprecated Qwen 3.6 27B in September 2026; Qwen 3.8 27B is its current 27B successor.

* Endpoint: `https://api.groq.com/openai/v1/chat/completions`
* Model: `qwen/qwen3.8-27b`
* Secret: `GROQ_API_KEY`, provided only through environment/secrets configuration
* Tool calls use the existing explicit approval and risk-verification process.

Create a key at <https://console.groq.com/keys>. Configure `GROQ_API_KEY` in the Render dashboard; no API key is committed in this repository.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLM_PROVIDER` | `groq` | `groq`, `ashna`, `ollama`, or `openai_compatible` |
| `GROQ_API_KEY` | — | Required when `LLM_PROVIDER=groq` |
| `GROQ_BASE_URL` | `https://api.groq.com/openai/v1` | Groq OpenAI-compatible base URL |
| `GROQ_MODEL` | `qwen/qwen3.8-27b` | Model id sent to Groq |
| `LLM_TIMEOUT_SECONDS` | `60` | Per-request timeout |

### Local development without a hosted key

Set `LLM_PROVIDER=ollama` and run a local Ollama (Docker Compose wires the `ollama` service
container for you), or point `LLM_PROVIDER=openai_compatible` at any OpenAI-compatible
endpoint. This keeps the backend fully functional offline.

> `LLM_PROVIDER=ollama` only makes sense locally: a `localhost` Ollama is not reachable from
> Render. Because settings validation is shared by the app and Alembic, local `alembic` runs
> also need either a real `GROQ_API_KEY` or an explicit `LLM_PROVIDER=ollama` override.

### Implemented behavior (tool calling & streaming)

* **Tool calling is native.** `ashna-x1` supports OpenAI-style client tools, so the router
  sends the MCP tool schemas as `tools` with `tool_choice: "auto"` and parses the returned
  `tool_calls`. No prompt-based JSON fallback is needed (the Ollama path also passes `tools`
  through). Proposed calls are still only proposals: nothing executes until the explicit
  confirmation step with fresh signed verification (AGENTS.md rule 6).
* **Streaming:** the Ashna adapter translates Ashna's OpenAI SSE stream into the router's
  internal token-stream shape (unit-tested in `tests/test_ashna_adapter.py`). The WebSocket
  contract is unchanged either way: the client receives `assistant.token` events followed by
  `assistant.done` (and `tool.request` for proposals), exactly as before. The WS route
  currently emits those token events from the completed response; wiring the adapter's
  `stream()` through the WS path is a future latency optimization, deliberately not done in
  this infrastructure change so the event ordering and partial-failure semantics stay
  identical.
* **Untrusted content** fetched from GitHub/email/external sources is passed to the model
  only inside explicit `<<<UNTRUSTED_EXTERNAL_CONTENT>>>` delimiters as data, never merged
  into the system/instruction prompt (AGENTS.md rule 7; see
  `app/chat/llm_core.py:delimit_untrusted_content`).

## Run locally (local libSQL file)

```bash
cp .env.example .env
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

The default `DATABASE_URL=sqlite+libsql:///./armx.db` uses the libSQL driver against a local
file (the same dialect path used against Turso, so local and deployed behavior match). Point
`DATABASE_URL` at a Turso URL (`libsql://<db>-<org>.turso.io`) plus `TURSO_AUTH_TOKEN` to run
against a remote database; local SQLite files are rejected in `staging`/`production` because
hosted filesystems are ephemeral. Use four slashes for an absolute local path
(`sqlite+libsql:////abs/path.db`), or `sqlite+aiosqlite://` for the plain SQLite driver.

Before first startup, set a persistent random `JWT_SECRET_KEY` and a strong
`BOOTSTRAP_ADMIN_PASSWORD` in `.env`. Generate a signing secret without putting it in shell
history, for example:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

The generated key and bootstrap password are credentials: keep them in an ignored `.env` or
secrets manager, never commit them. If no JWT key is supplied in local/demo mode, the service
generates a temporary key and logs that sessions and encrypted pairing credentials will be
invalid after restart. If no bootstrap password is supplied, no owner account is created.

```bash
alembic upgrade head              # needs GROQ_API_KEY, or: LLM_PROVIDER=ollama alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

With the example profile, `DEMO_INSECURE=true` explicitly enables local HTTP and emits a
startup warning. `/health` returns `server_version`, `requires_pairing`, and `at` when the
database is reachable. Do not expose this demo profile to the public internet.

## Docker Compose demo (offline fallback)

```bash
cp .env.example .env
# Set JWT_SECRET_KEY and BOOTSTRAP_ADMIN_PASSWORD in .env first.
docker compose up --build
```

Compose starts the API, a TLS-enabled Mosquitto broker, and Ollama; the API container applies
migrations before serving and stores the libSQL database file in a named volume, so nothing
depends on Render-style ephemeral storage. Only the API port is published to the host; the
database is a local file and the MQTT port is internal to the Compose network. The demo broker
uses an ephemeral self-signed TLS certificate and anonymous clients on that same private
network; it stands in for the external managed broker used in production and is **not** a
production broker configuration. Do not connect untrusted containers to the Compose network.

In production the broker is external: ESP32 devices and this backend both connect **out** to
it over MQTT/TLS (typically port 8883), and Render never exposes a broker port. See
[`docs/deploy-render.md`](docs/deploy-render.md).

The API is at `http://localhost:8000`. To use the local model, pull it once:

```bash
docker compose exec ollama ollama pull qwen2.5:3b
```

## Initial owner, pairing, and hardware provisioning

Set `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_EMAIL`, and `BOOTSTRAP_ADMIN_PASSWORD`
before first startup. The default owner public ID is `user-mohiur`. Pairing requests are
approved/rejected from a trusted operator host (never by printing a credential):

```bash
python -m app.pairing.cli approve <device-id>
# or
python -m app.pairing.cli reject <device-id>
```

Pairing polls use a device-signed Ed25519 challenge, and the approved device key is returned
once. The exact polling protocol is in `API_GAPS.md` and must be reflected in the Flutter
client before treating it as a stable published contract.

Resource hardware is provisioned out of band because `docs/api.md` does not define a device
registration route. Example:

```bash
python -m app.devices.cli resource \
  --id garage-controller --owner user-mohiur --name "Garage controller" \
  --site home --risk-tier MEDIUM \
  --relay "light,Garage light,MEDIUM,false"
```

Repeat `--relay` for each server-policy-configured relay. IDs and sites become MQTT topic
components; use simple letters, digits, dots, underscores, or hyphens. Devices remain offline
until valid MQTT state telemetry arrives. Risk tiers supplied by clients are ignored in favor
of the operator-provisioned relay policy.

`python -m app.devices.cli unlock-target ...` can register an informational target for the
Flutter list, but it does not enable actuation: no authenticated unlock-agent transport or
acknowledgement protocol is defined/configured, so signed requests currently return `FAILED`.

## Implemented behavior and intentional limits

- `/auth`: paired-device login, access/refresh rotation, logout, and revoked-session checks.
- `/devices/pair`: owner approval is out of band; credentials are delivered once after a
  signed challenge poll. `/devices` lists only the authenticated user's provisioned resources.
- `/admin` and `/audit`: session-authenticated admin controls, explicit kill/re-enable calls,
  immediate task/WebSocket cancellation, device revocation, and append-oriented audit queries.
- `/ws`: authenticated chat, assistant token/done events, and explicit tool proposals. Every
  write requires a separate confirmation and fresh signed verification. GitHub tools are
  owner/admin-only; email/contact tools are disabled until recipient consent is specified.
- `/v1/intercom`: each recipient device needs its own explicit opt-in. Every delivery,
  rejection, consent change, and missed attempt is audited. Offline recipients are not queued.
  Audio is not verification evidence and is never sent to the LLM.
- `/rules`: owner-scoped rule storage and dry-run previews only. There is no background rule
  evaluator/actuator until its trigger and consent semantics are specified.
- `/unlock`: verifies a signed, fresh, replay-protected HIGH-risk request but cannot actuate
  without the missing unlock-agent protocol.
- `/health`: database readiness using the documented response fields.

No raw biometric data is accepted for policy verification or written to logs/database; the
backend accepts only short-lived device-signed assertions. Risk tiers are
server-authoritative: LOW requires face evidence, MEDIUM face plus voice, and HIGH face plus
voice plus system biometric/PIN evidence. Voice alone never satisfies even LOW.

## Science Fair Demo Runbook

Two paths are supported. **Hosted (primary):** Render + Turso + Groq Qwen 3.8 27B + the
external MQTT broker — best if the venue has reliable internet. **Local fallback:** the
Docker Compose stack with local Mosquitto and Ollama — use it if the internet or Render is
unavailable on the day. Both use only synthetic/demo evidence; never real biometric data.

### Path A — hosted demo (Render)

1. **Warm the service before judging.** Ideally the service already runs on the smallest paid
   instance (`0.5c-512mb`, $7/mo, never sleeps). If it is on the free plan, start an external
   pinger on `/health` every ~10 minutes well before the demo, and run one manual warm-up
   request right before presenting (≈1-minute cold start on the free tier):

   ```bash
   curl --fail --max-time 120 https://<service-name>.onrender.com/health
   ```

2. **Verify from the client.** Point the Flutter app at
   `https://<service-name>.onrender.com` (socket `wss://…/ws`), sign in, and send one chat
   message; a streaming `assistant.token`/`assistant.done` reply proves WSS, Turso, and the
   Ashna provider path in one shot.
3. **Show a device round trip.** Publish simulated state to the external broker (replace the
   host/credentials with your HiveMQ values) and watch the `device.state` event arrive:

   ```bash
   mosquitto_pub -h <broker-host> -p 8883 --cafile /etc/ssl/certs/ca-certificates.crt \
     -u <backend-user> -P '<password>' -q 1 \
     -t armx/fair/fair-lamp/state \
     -m '{"firmware":"demo-1.0","relays":[{"id":"relay-main","state":"OFF"}],"sensors":[]}'
   ```

4. **Exercise only LOW-risk, consented interactions**, then show the admin kill-switch lock
   and explicit re-enable, and review the mutual audit trail. Keep all verification local to
   the device and use synthetic/demo evidence only.

### Path B — local fallback (Docker Compose)

If the venue internet or Render is unavailable, switch to the Compose stack, which runs
without external credentials:

```bash
cp .env.example .env
# Set a unique JWT_SECRET_KEY and BOOTSTRAP_ADMIN_PASSWORD in .env.
docker compose up --build
docker compose exec ollama ollama pull qwen2.5:3b   # once; Compose already sets LLM_PROVIDER=ollama
```

Wait for the API health check, then on the Docker host run:

```bash
curl --fail http://127.0.0.1:8000/health
```

The phone/emulator must use the host's LAN address, not `localhost` or `127.0.0.1` (those
addresses refer to the phone itself). HTTP is available only because `.env.example` opts in
to `DEMO_INSECURE=true`; the backend logs a warning. Keep the phone, laptop, and demo hardware
on a trusted local network.

Provision a demo device (the default bootstrap owner's public ID is `user-mohiur`; use the ID
matching your configured bootstrap username if it differs):

```bash
docker compose exec backend python -m app.devices.cli resource \
  --id fair-lamp --owner user-mohiur --name "Science fair lamp" \
  --site fair --risk-tier MEDIUM \
  --relay "relay-main,Demo lamp,MEDIUM,false"
```

For a simulated MQTT state update from inside the Compose network:

```bash
docker compose exec mosquitto mosquitto_pub \
  -h localhost -p 8883 --cafile /mosquitto/certs/server.crt -q 1 \
  -t armx/fair/fair-lamp/state \
  -m '{"firmware":"demo-1.0","relays":[{"id":"relay-main","state":"OFF"}],"sensors":[]}'
```

The backend should mark the provisioned device online and publish a `device.state` event to
the owning user's authenticated socket. MQTT telemetry is not cryptographic device
attestation, and broker publish acceptance is not proof that hardware changed state. For a
real lamp, use a separately reviewed device/firmware installation and the documented relay
policy; do not connect an unknown device to this broker.

### Flutter-through-backend sequence and current blocker (both paths)

The intended supervised run is: configure the Flutter client to the base URL (Render or LAN);
complete the approved-device pairing flow; log in; display the MQTT-updated device; exercise
only a LOW-risk, consented demo interaction; show the admin kill-switch lock and explicit
re-enable; then review the mutual audit trail. Follow `docs/api.md` for documented paths and
payloads; do not copy provisional WebSocket or assertion examples from this README into
Flutter.

**This end-to-end Flutter sequence cannot currently be completed against this backend.** The
reviewed Flutter tree has `MockArmxApi` but no concrete `RestArmxApi` in `lib/data/api/rest/`,
and its documented pairing/command/unlock payloads differ from the backend protocols.
Reconcile those items in [`API_GAPS.md`](API_GAPS.md) and implement the real Flutter
REST/WebSocket adapter before advertising a live Flutter-to-backend flow. Docker/Flutter are
unavailable in the validation sandbox; no real Compose or Flutter-through-backend smoke test
is claimed here.

**Do not demonstrate an actual unlock:** the backend has no authenticated unlock-agent
transport or acknowledgement and intentionally returns `FAILED` rather than claiming that a
lock opened. **Do not demonstrate contact/email access:** it is disabled pending explicit
per-person consent semantics. Rules are stored and dry-run only; they do not dispatch actions.

## Deployed profile checklist

The Compose file is a local/demo setup, not a production deployment template. The supported
production shape is Render + Turso + an external MQTT broker + Groq Qwen 3.8 27B
([`docs/deploy-render.md`](docs/deploy-render.md)). Outside the explicit local/demo profile:

- `ENVIRONMENT=staging`/`production`, `DEMO_INSECURE=false`, HTTPS/WSS through a trusted TLS
  terminator (Render: `uvicorn ... --proxy-headers --forwarded-allow-ips='*'`), with
  `ALLOW_PLAIN_HTTP_HEALTH_PROBE=true` excepting only the platform's parameterless
  `GET /health` probe.
- `PUBLIC_API_BASE_URL`, remote `libsql://` URL + `TURSO_AUTH_TOKEN`, persistent random
  `JWT_SECRET_KEY` (≥32 chars), owner password ≥12 chars, a `GROQ_API_KEY`, and an external
  TLS MQTT broker with non-anonymous credentials — all secrets in env vars/a secrets manager.
- No state on local disk: the filesystem is ephemeral. Migrations are a controlled deployment
  step (`alembic upgrade head` runs in the Render start command; use `preDeployCommand` on
  paid multi-instance plans).

## Development checks

```bash
ruff check .
mypy app
pytest -q
alembic check          # needs GROQ_API_KEY, or: LLM_PROVIDER=ollama alembic check
```

A local libSQL file is the default for development and tests; set `DATABASE_URL` to a remote
`libsql://<db>-<org>.turso.io` URL (with `TURSO_AUTH_TOKEN`) to exercise Turso, or to
`sqlite+aiosqlite://` for the plain SQLite driver. Set
`ARMX_TEST_DATABASE_URL="sqlite+libsql:////tmp/armx-suite-test.db"` to run the test suite
through the libSQL dialect. See `API_GAPS.md` for protocol additions, missing contract
schemas, and current transport assumptions.
