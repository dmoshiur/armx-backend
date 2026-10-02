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
