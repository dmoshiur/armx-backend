# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

# A.R.M.X AI Backend

Python 3.12 / FastAPI backend for A.R.M.X AI. It includes async SQLAlchemy persistence,
Alembic migrations, paired-device authentication, server-side signed risk verification,
admin controls, audit, WebSocket chat/tool proposals, consent-gated intercom, activity-rule
storage and dry runs, and TLS-only MQTT telemetry/command publishing. The published Flutter
contract at `dmoshiur/armx/docs/api.md` is authoritative; known additions and ambiguities are
tracked in [`API_GAPS.md`](API_GAPS.md), not silently treated as contract guarantees.

## Run locally (SQLite)

```bash
cd backend_python
cp .env.example .env
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

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
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

With the example profile, `DEMO_INSECURE=true` explicitly enables local HTTP and emits a
startup warning. `/health` returns `server_version`, `requires_pairing`, and `at` when the
database is reachable. Do not expose this demo profile to the public internet.

## Docker Compose demo

```bash
cd backend_python
cp .env.example .env
# Set JWT_SECRET_KEY and BOOTSTRAP_ADMIN_PASSWORD in .env first.
docker compose up --build
```

Compose starts the API, PostgreSQL, an internal TLS-enabled Mosquitto broker, and Ollama;
the API container applies migrations before serving. PostgreSQL and MQTT ports are not
published to the host. The disposable demo Postgres configuration trusts connections only
inside the private Compose network. The demo broker uses an ephemeral self-signed TLS
certificate and anonymous clients on that same private network; this is **not** a production
broker configuration. Do not connect untrusted containers to the Compose network.

The API is at `http://localhost:8000`. To use the local model, pull it once:

```bash
docker compose exec ollama ollama pull qwen2.5:3b
```

Compose enables MQTT by default and points the backend at the internal broker. Physical
resource-device commands still require an operator-provisioned device and compatible device
firmware; a successful API response only means the QoS 1 MQTT publish was accepted, not that
hardware actuated. State telemetry is consumed from `armx/{site}/{device}/state` and commands
are published to `armx/{site}/{device}/cmd`.

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
- `/ws`: authenticated chat, streamed assistant events, and explicit tool proposals. Every
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
backend accepts only short-lived device-signed assertions. Risk tiers are server-authoritative:
LOW requires face evidence, MEDIUM face plus voice, and HIGH face plus voice plus system
biometric/PIN evidence. Voice alone never satisfies even LOW.

## Science Fair Demo Runbook

This sequence is designed for a **local, supervised demo network**. It uses no real camera,
voice, contact, or location data. Do not expose the insecure demo profile to the public
internet.

### 1. Start the backend stack

```bash
cd backend_python
cp .env.example .env
# Set a unique JWT_SECRET_KEY and BOOTSTRAP_ADMIN_PASSWORD in .env.
docker compose up --build
```

Wait for the API health check, then on the Docker host run:

```bash
curl --fail http://127.0.0.1:8000/health
```

The phone/emulator must use the host's LAN address, not `localhost` or `127.0.0.1` (those
addresses refer to the phone itself). HTTP is available only because `.env.example` opts in
to `DEMO_INSECURE=true`; the backend logs a warning. Keep the phone, laptop, and demo hardware
on a trusted local network. In the terminal used to populate the model, pull Ollama once:

```bash
docker compose exec ollama ollama pull qwen2.5:3b
```

### 2. Provision a demo device and send simulated telemetry

The API intentionally has no undocumented resource-device registration route. Register one
from the trusted backend container; the default bootstrap owner's public ID is
`user-mohiur` (use the ID matching your configured bootstrap username if it differs):

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

### 3. Flutter-through-backend sequence and current blocker

The intended supervised run is: configure the Flutter client to the laptop's LAN base URL;
complete the approved-device pairing flow; log in; display the MQTT-updated device; exercise
only a LOW-risk, consented demo interaction; show the admin kill-switch lock and explicit
re-enable; then review the mutual audit trail. Keep all verification local to the device and
use synthetic/demo evidence only. Follow `docs/api.md` for documented paths and payloads; do
not copy provisional WebSocket or assertion examples from this backend README into Flutter.

**This end-to-end Flutter sequence cannot currently be completed against this backend.** The
reviewed Flutter tree has `MockArmxApi` but no concrete `RestArmxApi` in
`lib/data/api/rest/`, and its documented pairing/command/unlock payloads differ from the
backend protocols. Reconcile those items in [`API_GAPS.md`](API_GAPS.md), implement the real
Flutter REST/WebSocket adapter, and run the demo on a Docker-capable host before advertising a
live Flutter-to-backend flow. Docker and Flutter are unavailable in the validation sandbox;
no real Compose or Flutter-through-backend smoke test is claimed here.

**Do not demonstrate an actual unlock:** the backend has no authenticated unlock-agent
transport or acknowledgement and intentionally returns `FAILED` rather than claiming that a
lock opened. **Do not demonstrate contact/email access:** it is disabled pending explicit
per-person consent semantics. Rules are stored and dry-run only; they do not dispatch actions.

## Deployed profile checklist

This Compose file is a local/demo setup, not a production deployment template. Outside the
explicit local/demo profile:

- Set `ENVIRONMENT=staging` or `production`, `DEMO_INSECURE=false`, and use HTTPS/WSS through
  a trusted TLS terminator. Configure the ASGI server to trust forwarded scheme headers only
  from that proxy; the app does not trust caller-supplied forwarding headers directly.
- Set `PUBLIC_API_BASE_URL` to the public HTTPS API origin, use PostgreSQL with
  `DATABASE_URL=postgresql+asyncpg://.../armx?ssl=require` (or stronger certificate
  verification), and provide a persistent random `JWT_SECRET_KEY` of at least 32 characters.
  Use an HTTPS LLM endpoint outside explicit demo mode.
- Set an owner password of at least 12 characters. Store all secrets in a secrets manager.
- If MQTT is enabled, configure TLS CA validation, non-anonymous broker authentication, and
  topic ACLs. Per-device MQTT attestation and command acknowledgements are not defined by the
  current contract; do not treat broker telemetry as proof of physical execution.
- Apply migrations as a controlled deployment step and verify backups, logging, network
  policy, and retention before exposing user data.

## Development checks

```bash
cd backend_python
ruff check .
mypy app
pytest -q
alembic check
```

SQLite is the default for local development; set `DATABASE_URL` to a supported
`sqlite+aiosqlite://` or `postgresql+asyncpg://` URL as appropriate. See `API_GAPS.md` for
protocol additions, missing contract schemas, and current transport assumptions.
