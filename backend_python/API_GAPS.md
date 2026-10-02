# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

# Flutter API contract deviations and unresolved decisions

Source reviewed: [`dmoshiur/armx/docs/api.md`](https://github.com/dmoshiur/armx/blob/main/docs/api.md)
on 2026-10-02. That file is authoritative. This report distinguishes matching route names
from matching request/response behavior; implementation of a route does **not** imply full
contract conformance. Do not resolve these items by guessing a payload or weakening policy.

## Implemented route families

The backend contains `/health`, `/auth`, `/devices`, `/audit`, `/admin`, `/unlock`, `/rules`,
`/v1/intercom`, and `/ws`. The route names substantially overlap with `docs/api.md`, but the
contract deviations and absent behavior below must be resolved before a Flutter production
demo can be claimed. REST errors use `{code, message, retryable, request_id}`.

## Explicit differences from `docs/api.md`

1. **Device pairing does not use the documented polling exchange.** The Flutter contract
   describes repeating the same `POST /devices/pair` body while pending and receiving a
   stable device ID, then a `200` approved response or `403 auth_pairing_rejected`. The backend
   instead returns a challenge on initial submission, requires every poll to carry a
   detached Ed25519 signature over canonical JSON, rotates the challenge, and requires a
   trusted operator to approve or reject out of band with
   `python -m app.pairing.cli approve|reject <device-id>`. An approved poll returns the
   device credential once. There is no HTTP owner-approval/rejection route. The Flutter
   pairing client must be changed or the backend protocol must be reconciled first.

2. **Unlock request signature fields and assertion requirement differ.** The documented
   signature covers canonical JSON `{device_id, nonce, exp, action}` and the `assertion` is
   optional. The backend requires `issued_at`, `algorithm`, `public_key`, a detached signature
   over `{action, algorithm, device_id, exp, issued_at, nonce, public_key}`, and a valid
   single-use HIGH-risk `owner_verified` assertion. The backend currently binds the outer
   signature to the authenticated requesting device's public key; the contract does not
   specify that binding. A timestamp must be timezone-aware and within the clock tolerance,
   and unlock TTL is at most 30 seconds. These canonicalization, key-binding, required-field,
   and assertion decisions need to be adopted in the client contract before unlock requests
   can be sent by Flutter.

3. **Device commands require an extra verification field and have a different result
   message.** `POST /devices/{id}/command` requires an `owner_verified` signed assertion in
   addition to the documented `command`, `parameters`, and `risk_tier`. The supplied risk
   tier is ignored; the backend derives the required tier from operator-provisioned relay
   policy. A successful publish response says it was accepted by secure MQTT and that physical
   state is unconfirmed, rather than claiming `Applied "relay:STATE"`. No physical actuation
   is reported as successful solely because MQTT accepted a QoS 1 publish.

4. **Additional Flutter-interface routes are not all enumerated in `docs/api.md`.** The
   backend adds `GET /admin/state`, `GET /unlock/paired-targets`, and
   `POST /unlock/revoke` (body `{ "target_id": "..." }`) based on Flutter interface/models.
   They are compatibility additions, not documented contract guarantees. The Flutter
   interface also references `activateScene`, `decideToolCall`, and `adminState`, but the
   contract does not define every corresponding HTTP/WebSocket request shape. There is no
   scene-activation route.

5. **Kill-switch re-enable shape is not documented.** Re-enable is an explicit, authenticated
   `POST /admin/kill` request with `engaged: false`; the backend does not expose a separate
   `/admin/revive` route. No risk-tier evidence is required, and re-enable is never an
   automatic side effect. If a distinct path or response is required, it needs a published
   schema.

6. **WebSocket inbound frames are provisional.** `docs/api.md` documents server-to-client
   events but does not define the complete client-to-server schema. The backend accepts
   `{"type":"chat.send","text":"...","conversation_id":"main","message_id":"optional"}`
   and `{"type":"tool.confirm","tool_call_id":"...","approve":true,"owner_verified":{...}}`.
   These frame names, fields, confirmation semantics, and unframed-error behavior must be
   confirmed against the Flutter client. The assertion is single-use and freshly verified;
   no write/send tool runs before explicit approval. The backend currently queues even LOW-tier
   read tools for a confirmation frame and signed assertion, while `docs/api.md` describes
   LOW calls as auto-approved without a card. That stricter behavior also needs client
   agreement; MEDIUM/HIGH actions remain explicitly confirmed and verified server-side.

7. **Owner-verification assertion wire format is a backend interpretation.** The contract
   refers to `owner_verified` but does not fully specify its token. The backend requires a
   device-signed compact EdDSA JWS with `iat`, `exp`, `jti`, `nonce`, `device_id`, `scope`,
   `single_use: true`, and signed evidence factors. It binds the token to the paired device,
   requires the `owner_verified` scope, rejects nonce replays, and limits validity to 60
   seconds (30 seconds for unlock). Optional outer `scope`, `iat`, and `exp` must match the
   signed claims. No raw biometric data is accepted.

8. **Intercom upload has an extra assertion and the API document's endpoint count is
   inconsistent.** The backend requires a signed LOW-tier `owner_verified` assertion on
   `POST /v1/intercom/announcements`; the documented multipart fields do not include it.
   The table lists seven operations although its introduction says “all six endpoints.”
   Multipart encoding/field name for the assertion needs agreement. Consent is device-local,
   revocable, checked again at delivery, and offline/rejected attempts are audited; offline
   announcements are not queued.

9. **Tool-execution HTTP routes and Email are absent.** The prompt/interface references
   MCP Email and HTTP execute routes, but `docs/api.md` does not define their schemas and the
   backend does not invent them. Tool proposals and decisions currently travel through the
   provisional WebSocket frames above. GitHub tools are optional and owner/admin-only;
   writes require explicit confirmation. Email/contact access and sends remain disabled
   until per-person, revocable, one-time consent is specified. No scene-activation endpoint
   is implemented.

10. **Activity rules are stored and dry-run only.** `/rules` validates, owner-scopes, stores,
    deletes, and previews rules. The dry run is descriptive and does not evaluate incoming
    activity/geofence/time/device-state events. There is no background rule evaluator,
    dispatch, or scene actuator. Trigger evaluation, consent, event-delivery semantics, and
    action acknowledgement need an agreed contract first.

11. **Unlock actuation is deliberately unavailable.** No authenticated unlock-agent transport,
    topic, or acknowledgement protocol is defined/configured. A fresh signed request is
    validated and audited, but a reachable target currently produces `FAILED` with an
    explicit “transport is not connected” message; stale/offline targets produce
    `target_offline`. The backend never claims that a physical lock opened.

12. **Admin tool response shape and scene behavior are not fully specified.** The backend's
    `POST /admin/tools` returns the current tool-toggle list; the contract documents the
    request but does not define that response. Mail, privileged-system, and vision access
    cannot be enabled through a toggle. No `activateScene` behavior is inferred from
    `action_type: SCENE`.

## Security interpretations that remain authoritative

- The API table says LOW accepts face **or** voice, while `docs/voice.md` and project policy
  state voice alone never satisfies any tier. The server therefore requires signed face
  evidence for LOW; MEDIUM requires signed face **and** voice; HIGH requires face, voice, and
  system biometric/PIN evidence. All evidence must be signed, unexpired (at most 60 seconds),
  and supplied as an assertion; raw biometric input is rejected.
- `owner_verified` assertions are nonce-checked, replay-rejected, single-use, scoped, and
  expire in at most 60 seconds (30 seconds for unlock). Token claims, timestamps, device ID,
  and requested policy are checked server-side.
- Kill-switch actions require basic authenticated admin/owner session only, act immediately,
  cancel tracked work, and close sockets. A separate explicit authenticated request is
  required to re-enable.
- Intercom reaches only explicitly opted-in recipient devices. Delivery and rejected/missed
  attempts are audited and queryable through the shared audit trail. Audio is not verification
  evidence and is never sent to the LLM.
- TLS is required outside explicit local/demo mode. `DEMO_INSECURE=true` logs a startup
  warning and is not a production setting. Secrets and raw biometrics are not logged or
  stored; external content is delimited as untrusted data before being shown to the LLM.

## Flutter integration blocker

The reviewed Flutter repository has `MockArmxApi` but no concrete `RestArmxApi` in
`lib/data/api/rest/` (only the auth interceptor was present). The documented `USE_MOCK=false`
switch therefore does not yet provide a real Flutter-to-backend client. In addition to
reconciling the protocol differences above, the Flutter project needs a concrete REST and
WebSocket implementation before an end-to-end Science Fair demo can be truthfully reported.
