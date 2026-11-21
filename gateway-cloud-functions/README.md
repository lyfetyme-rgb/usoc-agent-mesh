# Gateway Cloud Functions

Self-contained Firebase Cloud Functions (TypeScript, Node 20) for ROK-01 facility
gateway telemetry. It implements five functions:

| Function | Type | Purpose |
| --- | --- | --- |
| `ingestGatewayTelemetry` | HTTPS | One-way telemetry ingress, token auth, server-side critical-limit detection, 30-day TTL, atomic hourly rollups |
| `checkGatewayHeartbeats` | Scheduler (1 min) | Flips gateways silent for >180 s to `OFFLINE` and raises a critical connectivity alert |
| `dispatchAlertNotification` | Firestore trigger | Texts the on-duty technician with a one-tap deep link on new alerts |
| `dispatchCustomerRequestNotification` | Firestore trigger | Texts the on-duty technician when a Customer Request Form is created |
| `provisionTenantAndGateway` | HTTPS (admin) | Creates a tenant + gateway, discloses the raw token once, returns the printable QR sticker URL |
| `issueHliftAssertion` | HTTPS (IdP callback) | Verifies the IdP session, issues the signed `hlift_assertion` cookie for H-LIFT, redirects to the app |

All Firestore access uses the Admin SDK. Client reads/writes are denied by
`firestore.rules` — telemetry can only enter through the HTTPS data diode.

## Layout

```
gateway-cloud-functions/
  firebase.json
  firestore.rules
  firestore.indexes.json
  .firebaserc.example
  functions/
    src/index.ts              # function exports
    src/config.ts             # env-backed configuration
    src/types.ts              # Firestore document shapes
    src/lib/                  # auth, validation, rollups, alerts, QR, Twilio, heartbeat
    src/functions/            # the five function handlers
    test/                     # Vitest unit + handler tests (in-memory Firestore fake)
```

## Setup

```bash
cd gateway-cloud-functions/functions
npm install
cp .env.example .env              # fill in values (see below)
cp ../.firebaserc.example ../.firebaserc
npm run build
npm test
```

Firebase CLI loads `functions/.env` automatically for local emulation and
deployment. For production, prefer `firebase functions:secrets:set` over a
committed env file.

### Environment variables

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_BASE_URL` | `https://app.example.com` | Operator app origin. Used for activation/sticker/deep links. |
| `APP_DEEP_LINK_SCHEME` | unset | e.g. `rok` → `rok://alerts/<id>`; otherwise HTTPS universal link. |
| `TWILIO_ACCOUNT_SID` | — | Required to send SMS. |
| `TWILIO_AUTH_TOKEN` | — | Required to send SMS. |
| `TWILIO_FROM_NUMBER` | — | E.164 sender number. |
| `ALERT_FALLBACK_PHONE` | unset | Optional fallback when a tenant has no on-duty technician. |
| `TELEMETRY_MAX_BODY_BYTES` | `4096` | Strict `<` limit: a body of exactly 4096 bytes is rejected. |
| `TELEMETRY_TTL_DAYS` | `30` | Sets `expireAt` on raw packets. |
| `GATEWAY_OFFLINE_THRESHOLD_MS` | `180000` | Silence threshold for the watchdog. |
| `HEARTBEAT_SCHEDULE` | `every 1 minute` | Cloud Scheduler expression. |
| `BREACH_ALERT_COOLDOWN_MS` | `300000` | Reserved for future SMS rate limiting. |

## Firestore TTL policy

The TTL policy is a database-level setting, not a Firestore index, so it must
be enabled once (or the raw packets will never be deleted):

```bash
gcloud firestore ttl create --collection-group=packets \
  --field=expireAt --project=<your-project-id>
```

Or configure it in the Firebase console: Firestore → TTL policies → add policy
on `expireAt` for all `packets` subcollections.

## Indexes and deploy

`firestore.indexes.json` contains the collection-group index for
`gateways.lastSeenAt`, used by the watchdog. Deploy everything from
`gateway-cloud-functions/`:

```bash
firebase deploy --only firestore:rules,firestore:indexes,functions
```

Admin onboarding requires Firebase Auth users with the custom claim
`admin: true`:

```bash
node -e "
const { initializeApp, applicationDefault } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
initializeApp({ credential: applicationDefault() });
getAuth().setCustomUserClaims('<admin-uid>', { admin: true });
"
```

## API contracts

### `POST /ingestGatewayTelemetry`

Headers:

- `X-Gateway-ID: <gatewayId>`
- `X-Gateway-Token: <rawToken>` (or `Authorization: Bearer <rawToken>`)

Body: a **flat JSON object of finite numbers only**, strictly smaller than 4 KB.
No strings, booleans, nulls, arrays or nested objects. Maximum 64 metrics.

```json
{"temp": 72.5, "vibration": 3.1, "pressure": 101.3}
```

Responses: `204` on success (no payload — the device receives no data or
commands), `400` invalid payload, `401` bad credentials, `405` wrong method,
`413` oversized body.

Side effects in one transaction:

1. Raw packet written with `expireAt = now + 30 days`.
2. Hourly rollup doc upserted (`min`, `max`, `breachCount`, `sampleCount`).
3. Gateway `status` set to `ONLINE` and `lastSeenAt` refreshed; offline alert
   cleared if this packet ends an offline episode.
4. Breach alerts opened/updated or cleared per metric.
5. Token doc marked `activatedAt` / `lastUsedAt`.

### `GET|POST /issueHliftAssertion`

H-LIFT signed-assertion (Zero Trust) callback. Authenticates with the IdP
session cookie (`HLIFT_IDP_SESSION_COOKIE`, default `__session`), verified by
Firebase Admin with revocation checking. Server-to-server callers may use
`Authorization: Bearer <firebase-id-token>` instead. There is no request body:
the verified uid is mapped to an H-LIFT subject through `HLIFT_SUBJECT_MAP` and
must also appear in `HLIFT_ALLOWED_SUBJECTS`.

Successful response: `302` to `APP_BASE_URL` with `Cache-Control: no-store` and:

```
Set-Cookie: hlift_assertion=<HS256 JWT>; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600
Set-Cookie: hlift_subject=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0
```

Set `HLIFT_COOKIE_DOMAIN` only when the gateway and H-LIFT live on different
subdomains of one registrable domain. H-LIFT must use the same
`HLIFT_IDP_HMAC_SECRET`, `HLIFT_IDP_ISSUER` and `HLIFT_IDP_AUDIENCE`, with
`HLIFT_ZERO_TRUST=1`.

Responses: `302` issued, `401` missing/invalid IdP credential, `403` unmapped
uid or subject outside the allowlist, `405` wrong method.

### `POST /provisionTenantAndGateway`

Requires `Authorization: Bearer <admin-id-token>`.

```json
{
  "tenantName": "North Facility",
  "gatewayLabel": "Boiler Room ROK-01",
  "onDutyTechnicianId": "tech-7",
  "criticalLimits": { "temp": { "max": 80 } },
  "globalCriticalLimit": 500
}
```

Returns `201`:

```json
{
  "tenantId": "…",
  "gatewayId": "…",
  "model": "ROK-01",
  "rawToken": "…",
  "activationUrl": "https://app.example.com/activate#g=…&t=…",
  "qrStickerUrl": "https://app.example.com/stickers/…#t=…",
  "qrSvgDataUrl": "data:image/svg+xml;base64,…",
  "notice": "rawToken is returned once. Only its SHA-256 hash is stored."
}
```

The raw token appears only in this response and in the URL fragment (fragments
are never sent in HTTP requests, so scanner logs cannot capture it). Only its
SHA-256 hex digest is stored, as the ID of `gatewayTokens/{hash}`.

## Firestore data model

```
tenants/{tenantId}                         name, status, onDutyTechnicianId
tenants/{tenantId}/gateways/{gatewayId}    model, tokenHash, status, criticalLimits,
                                           lastSeenAt?, offlineSince?
tenants/{tenantId}/gateways/{gatewayId}/packets/{packetId}
                                           readings, receivedAt, expireAt, breaches
tenants/{tenantId}/gateways/{gatewayId}/rollups/{YYYY-MM-DDTHH}
                                           min, max, breachCount, sampleCount
gatewayTokens/{sha256hex}                  tenantId, gatewayId, activatedAt?, revokedAt?
alerts/{alertId}                           kind, tenantId, gatewayId?, message, status
customerRequests/{requestId}               tenantId, subject, …
technicians/{technicianId}                 phone, name
```

Deterministic alert IDs (`breach_<gateway>_<metric>` and
`connectivity_<gateway>`) make each breach/offline episode fire exactly one SMS
on creation. A metric returning to range, or a gateway coming back online,
deletes its alert so a future episode creates a new one.

## Testing

```bash
cd gateway-cloud-functions/functions
npm test          # 59 tests, no emulator required
npm run build     # strict TypeScript compile
```

Handler tests use an in-memory Firestore fake (`test/helpers/fakeFirestore.ts`)
and mocked Firebase/Twilio modules, so they run offline and deterministically.

## Operational notes

- The watchdog uses a single-field collection-group query and filters status in
  code to avoid composite index requirements.
- New gateways omit `lastSeenAt` until their first packet, so provisioning does
  not immediately produce a false offline alert.
- If Twilio or on-duty configuration is missing, SMS dispatch logs a warning and
  skips rather than retrying endlessly; the alert remains in Firestore.
- `dispatchAlertNotification` marks `notifiedAt` after a successful send,
  providing idempotency across trigger redeliveries.
