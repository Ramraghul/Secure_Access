# API Reference

The interactive, always-current reference is **Swagger UI** — [local](http://localhost:4000/api-docs/) or [deployed](https://secure-access-a8j6fkex8-ramraghuls-projects.vercel.app/api-docs/) (raw spec: `/swagger.json`). Its *Servers* dropdown switches between Local and Deployed.
This page is a readable companion: conventions, every endpoint grouped by feature, request/response examples, and the complete error catalogue.

## Contents

1. [Conventions](#1-conventions)
2. [Authentication](#2-authentication)
3. [MFA](#3-mfa)
4. [Sessions & profile](#4-sessions--profile)
5. [Devices](#5-devices)
6. [Users (admin)](#6-users-admin)
7. [Roles & permissions (admin)](#7-roles--permissions-admin)
8. [Audit trail (admin)](#8-audit-trail-admin)
9. [OpenID Connect](#9-openid-connect)
10. [System](#10-system)
11. [Error catalogue](#11-error-catalogue)
12. [End-to-end curl walkthrough](#12-end-to-end-curl-walkthrough)

---

## 1. Conventions

| Topic | Rule |
|---|---|
| Base URLs | Local `http://localhost:4000` · Deployed `https://secure-access-a8j6fkex8-ramraghuls-projects.vercel.app` |
| Base path | `/api/v1` (except `/health`, `/.well-known/openid-configuration`, `/swagger.json`, `/api-docs`) |
| Format | JSON request and response bodies (`Content-Type: application/json`). The OIDC token and revoke endpoints also accept `application/x-www-form-urlencoded`. |
| Authentication | `Authorization: Bearer <accessToken>` |
| IDs | UUID v4. Malformed IDs return `400 VALIDATION_ERROR` |
| Errors | `{ "error": "CODE", "message": "…", "details": {…}?, "requestId": "…" }` |
| OAuth errors | `{ "error": "invalid_grant", "error_description": "…" }` (RFC 6749) |
| Tracing | Every response has `X-Request-Id`. Send your own (8–64 chars `[A-Za-z0-9-]`) to correlate |
| Pagination | `?page=1&limit=20` → `{ data: [...], pagination: { page, limit, total, totalPages } }` |
| Rate limits | `RateLimit-*` headers; `429 RATE_LIMITED` when exceeded |
| Timestamps | ISO 8601, UTC |

**Legend:** 🔓 public · 🔑 any signed-in user · 🛡️ requires a permission

---

## 2. Authentication

| | Method | Path | Purpose |
|---|---|---|---|
| 🔓 | POST | `/auth/register` | Create an account |
| 🔓 | POST | `/auth/login` | Password login (→ tokens, or 202 MFA challenge) |
| 🔓 | POST | `/auth/login/mfa` | Finish login with a TOTP or backup code |
| 🔓 | POST | `/auth/refresh` | Rotate refresh token, get a new access token |
| 🔑 | POST | `/auth/logout` | Revoke the current session |
| 🔑 | POST | `/auth/logout-all` | Revoke all sessions |

### POST `/auth/register`

```json
{ "email": "jane@example.com", "password": "Str0ng!Passphrase", "firstName": "Jane", "lastName": "Doe" }
```

`201`

```json
{ "message": "User registered successfully", "userId": "3b241101-e2bb-4255-8caf-4136c566a962" }
```

Errors: `400 VALIDATION_ERROR`, `400 WEAK_PASSWORD` (`details.password` lists failed rules), `409 EMAIL_EXISTS`.

### POST `/auth/login`

```json
{ "email": "jane@example.com", "password": "Str0ng!Passphrase" }
```

Optional fields: `totp_code` or `backupCode` (single-step MFA), `rememberDevice` (boolean, default `false` — after MFA succeeds, skip the code on this browser for 30 days).

`200` — signed in

```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9…",
  "refreshToken": "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b.qJ3v…",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "user": { "id": "…", "email": "jane@example.com", "firstName": "Jane", "lastName": "Doe", "mfaEnabled": false, "mustChangePassword": false },
  "mfa": "not_enabled",
  "device": { "id": "…", "name": "GNU/Linux Chrome", "isTrusted": false, "trustedUntil": null }
}
```

`mfa` says how the second factor was handled: `verified` (a code was checked), `trusted_device` (no code asked because this browser was remembered — see `device.trustedUntil`), or `not_enabled` (the account has no MFA).

`202` — MFA required (device not trusted)

```json
{ "mfaRequired": true, "mfaToken": "eyJ…", "expiresIn": 300, "message": "MFA code required. POST it with the mfaToken to /auth/login/mfa" }
```

Errors: `401 INVALID_CREDENTIALS`, `401 INVALID_MFA`, `403 ACCOUNT_DISABLED`, `423 ACCOUNT_LOCKED` (`details.lockedUntil`), `429 RATE_LIMITED`.

### POST `/auth/login/mfa`

```json
{ "mfaToken": "eyJ…", "code": "492039", "rememberDevice": true }
```

or `{ "mfaToken": "eyJ…", "backupCode": "9F2A7C1B3D" }`. Returns the same `200` body as login.
Errors: `401 INVALID_MFA_TOKEN` (expired, other device, wrong type), `401 INVALID_MFA`, `423 ACCOUNT_LOCKED`.

### POST `/auth/refresh`

```json
{ "refreshToken": "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b.qJ3v…" }
```

`200` → `{ accessToken, refreshToken, tokenType, expiresIn }`. **Store the new refresh token — the old one is now invalid.**
Errors: `401 INVALID_REFRESH_TOKEN`, `401 REFRESH_TOKEN_REUSED` (the session has been revoked).

### POST `/auth/logout` · POST `/auth/logout-all`

`200` → `{ "success": true, "message": "Logged out" }` · `{ "success": true, "revokedSessions": 3, … }`

---

## 3. MFA

| | Method | Path | Purpose |
|---|---|---|---|
| 🔑 | POST | `/auth/mfa/setup` | Generate secret, QR code and backup codes |
| 🔑 | POST | `/auth/mfa/verify` | Confirm the first code and enable MFA |
| 🔑 | POST | `/auth/mfa/disable` | Turn MFA off (password + code) |

### POST `/auth/mfa/setup`

`200`

```json
{
  "qrCode": "data:image/png;base64,iVBORw0KGgo…",
  "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
  "otpauthUrl": "otpauth://totp/SecureAccess%3Ajane%40example.com?secret=…&issuer=SecureAccess",
  "backupCodes": ["9F2A7C1B3D", "…"],
  "message": "Scan the QR code with your authenticator app, then call /auth/mfa/verify"
}
```

Errors: `403 PROTECTED_ACCOUNT`, `409 MFA_ALREADY_ENABLED`.

### POST `/auth/mfa/verify`

`{ "token": "492039" }` → `200 { success: true }`. Errors: `400 INVALID_MFA_CODE`, `400 MFA_NOT_INITIALIZED`, `409 MFA_ALREADY_ENABLED`.

### POST `/auth/mfa/disable`

`{ "password": "…", "code": "492039" }` (or `backupCode`) → `200`. Errors: `400 MFA_NOT_ENABLED`, `401 INVALID_CREDENTIALS`, `401 INVALID_MFA`, `403 PROTECTED_ACCOUNT`.

---

## 4. Sessions & profile

| | Method | Path | Purpose |
|---|---|---|---|
| 🔑 | GET | `/auth/me` | Profile, roles, effective permissions, devices |
| 🔑 | PATCH | `/auth/me` | Update first/last name |
| 🔑 | POST | `/auth/change-password` | Change password (signs out other sessions) |
| 🔑 | GET | `/auth/sessions` | Active sessions (first-party and OIDC) |
| 🔑 | DELETE | `/auth/sessions/{id}` | Revoke one session |

### GET `/auth/me`

```json
{
  "user": {
    "id": "…", "email": "auditor@secureaccess.dev", "firstName": "Avery", "lastName": "Auditor",
    "mfaEnabled": false, "isProtected": true, "mustChangePassword": false,
    "lastLoginAt": "2026-09-15T10:12:03.000Z", "createdAt": "2026-09-15T09:00:00.000Z",
    "roles": ["auditor"],
    "permissions": ["export:audit", "read:audit", "read:client", "read:role", "read:user"]
  },
  "devices": [{ "id": "…", "deviceName": "GNU/Linux Chrome", "ipAddress": "203.0.113.7", "isTrusted": false, "current": true, "lastUsedAt": "…", "firstUsedAt": "…" }],
  "sessionId": "…"
}
```

### POST `/auth/change-password`

`{ "currentPassword": "…", "newPassword": "…" }` → `200 { success, revokedSessions }`.
Errors: `400 WEAK_PASSWORD`, `400 PASSWORD_REUSE`, `401 INVALID_CREDENTIALS`, `403 PROTECTED_ACCOUNT`, `423 ACCOUNT_LOCKED`.

### GET `/auth/sessions`

```json
{
  "sessions": [
    { "id": "…", "current": true, "type": "first-party", "clientId": null, "clientName": null, "scope": null,
      "device": { "id": "…", "deviceName": "GNU/Linux Chrome", "isTrusted": false },
      "ipAddress": "203.0.113.7", "userAgent": "Mozilla/5.0 …", "createdAt": "…", "lastUsedAt": "…", "expiresAt": "…" },
    { "id": "…", "current": false, "type": "oidc", "clientId": "secureaccess-demo", "clientName": "SecureAccess Demo App",
      "scope": "openid profile email offline_access", "device": null, "…": "…" }
  ]
}
```

---

## 5. Devices

| | Method | Path | Purpose |
|---|---|---|---|
| 🔑 | GET | `/devices` | Your devices with active-session counts |
| 🔑 | GET | `/devices/current` | How the server identifies the calling device |
| 🔑 | POST | `/devices/{id}/trust` | Remember the device for 30 days (needs MFA on + a current code) |
| 🔑 | POST | `/devices/{id}/revoke` | Remove trust |
| 🔑 | DELETE | `/devices/{id}` | Forget the device and sign out its sessions |

`GET /devices/current` →

```json
{ "currentDevice": { "id": "…", "fingerprint": "5c1f…64 hex", "name": "GNU/Linux Chrome", "ipAddress": "203.0.113.7", "userAgent": "…", "isKnown": true, "isTrusted": false, "firstUsedAt": "…" } }
```

Other users' devices return `404 DEVICE_NOT_FOUND`.

### POST `/devices/{id}/trust`

Trust only exists to skip the MFA code, so it has to be confirmed with a second factor:

```json
{ "code": "492039" }
```

or `{ "backupCode": "9F2A7C1B3D" }` → `200 { success, message, trustedUntil }` (30 days from now, `TRUSTED_DEVICE_DAYS`).
Errors: `400 MFA_NOT_ENABLED` (turn MFA on first), `400 VALIDATION_ERROR` (no code), `401 INVALID_MFA`, `404 DEVICE_NOT_FOUND`, `423 ACCOUNT_LOCKED`.

Trust is cleared automatically when MFA is enabled or disabled and when the password is changed or reset.

---

## 6. Users (admin)

| | Method | Path | Permission |
|---|---|---|---|
| 🛡️ | GET | `/users?page&limit&search&status` | `read:user` |
| 🛡️ | GET | `/users/{id}` | `read:user` |
| 🛡️ | POST | `/users/{id}/deactivate` | `update:user` |
| 🛡️ | POST | `/users/{id}/activate` | `update:user` |
| 🛡️ | POST | `/users/{id}/reset-password` | `manage:user` |
| 🛡️ | DELETE | `/users/{id}` | `delete:user` |

- `status` is `active` or `inactive`; `search` matches email, first or last name (case-insensitive); `limit` ≤ 100.
- Responses never include `passwordHash`, `mfaSecret` or backup codes.
- Deactivate/reset revoke all the user's sessions and return `revokedSessions`.
- `POST /users/{id}/reset-password` → `{ success, temporaryPassword, revokedSessions, warning }`.
- Guards: `400 CANNOT_MODIFY_SELF` (deactivate/delete yourself), `403 PROTECTED_ACCOUNT`, `404 USER_NOT_FOUND`.

---

## 7. Roles & permissions (admin)

| | Method | Path | Permission |
|---|---|---|---|
| 🛡️ | GET | `/roles` | `read:role` |
| 🛡️ | GET | `/roles/{id}` | `read:role` |
| 🛡️ | POST | `/roles` | `create:role` |
| 🛡️ | PUT | `/roles/{id}` | `update:role` |
| 🛡️ | DELETE | `/roles/{id}` | `delete:role` |
| 🛡️ | POST | `/roles/{id}/assign` | `manage:user-role` |
| 🛡️ | POST | `/roles/{id}/revoke` | `manage:user-role` |

### POST `/roles`

```json
{
  "name": "support",
  "description": "Read-only user support",
  "permissions": [
    { "action": "read", "resource": "user" },
    { "action": "read", "resource": "audit" }
  ]
}
```

`201` → the role with `permissions` and `users`.

- `name`: lowercase letters, digits, `_`, `-` (2–50 chars).
- `action`: `create` · `read` · `update` · `delete` · `manage` (all actions) · `export`.
- `resource`: `user` · `role` · `user-role` · `audit` · `client` · `*` (all resources).
- `PUT` replaces the whole permission list when `permissions` is present.

### POST `/roles/{id}/assign` · `/revoke`

`{ "userId": "…" }` → `200`. Errors: `404 ROLE_NOT_FOUND`, `404 USER_NOT_FOUND`, `404 ROLE_NOT_ASSIGNED`, `403 PROTECTED_ACCOUNT`, `409 LAST_ADMIN`.

System roles (`admin`, `auditor`, `user`): only `description` can change (`403 SYSTEM_ROLE` otherwise), and they cannot be deleted.

---

## 8. Audit trail (admin)

| | Method | Path | Permission |
|---|---|---|---|
| 🛡️ | GET | `/audit` | `read:audit` |
| 🛡️ | GET | `/audit/events` | `read:audit` |
| 🛡️ | GET | `/audit/retention` | `read:audit` |
| 🛡️ | POST | `/audit/export` | `export:audit` |
| 🛡️ | POST | `/audit/purge` | `manage:audit` |

**`GET /audit` filters:** `page`, `limit` (≤ 500), `userId`, `event`, `action` (HTTP method), `resource` (substring), `ipAddress` (substring), `statusCode`, `startDate`, `endDate`.

```json
{
  "data": [{
    "id": "…", "userId": "…", "event": "LOGIN_FAILED", "action": "POST", "resource": "/api/v1/auth/login",
    "statusCode": 401, "ipAddress": "203.0.113.7", "userAgent": "…", "timestamp": "…",
    "metadata": {
      "requestId": "…", "device": "GNU/Linux Chrome", "durationMs": 231, "aborted": false,
      "requestBody": { "email": "jane@example.com", "password": "••••••" },
      "responseSnippet": "{\"error\":\"INVALID_CREDENTIALS\",…}", "details": null
    },
    "user": { "id": "…", "email": "jane@example.com", "firstName": "Jane", "lastName": "Doe" }
  }],
  "pagination": { "page": 1, "limit": 50, "total": 1, "totalPages": 1 }
}
```

**`GET /audit/events`** — flattened rows plus `suspicious` (off-hours external access). Filters: `userId`, `email`, `event`, `action`, `resource`, `ip`, `status`, `before`, `after`, `sensitive=true`, `limit` (≤ 1000).

**`GET /audit/retention`** → `{ totalRecords, last30Days, failedLoginsLast24h, oldestRecord, oldestRecordAgeDays, configuredRetentionDays, eventCounts, note }`.

**`POST /audit/export`** — CSV attachment (≤ 10,000 rows), accepts the `GET /audit` filters as query parameters.

**`POST /audit/purge`** — `{ "olderThanDays": 90 }` (default `AUDIT_RETENTION_DAYS`) → `{ success, deleted, cutoff }`.

### Audit event names

| Area | Events |
|---|---|
| Registration & login | `USER_REGISTERED`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGIN_MFA_REQUIRED`, `LOGIN_BLOCKED_LOCKED`, `LOGIN_BLOCKED_INACTIVE`, `ACCOUNT_LOCKED` |
| MFA | `MFA_SETUP_STARTED`, `MFA_ENABLED`, `MFA_VERIFY_FAILED`, `MFA_FAILED`, `MFA_DISABLED`, `MFA_DISABLE_FAILED` |
| Sessions | `TOKEN_REFRESHED`, `TOKEN_REFRESH_FAILED`, `REFRESH_TOKEN_REUSED`, `LOGOUT`, `LOGOUT_ALL`, `SESSION_REVOKED` |
| Profile | `PROFILE_UPDATED`, `PASSWORD_CHANGED`, `PASSWORD_CHANGE_FAILED` |
| Devices | `DEVICE_TRUSTED`, `DEVICE_TRUST_REVOKED`, `DEVICE_REMOVED` |
| Administration | `USER_ACTIVATED`, `USER_DEACTIVATED`, `USER_DELETED`, `PASSWORD_RESET_BY_ADMIN`, `ROLE_CREATED`, `ROLE_UPDATED`, `ROLE_DELETED`, `ROLE_ASSIGNED`, `ROLE_REVOKED`, `AUDIT_EXPORTED`, `AUDIT_PURGED` |
| OpenID Connect | `OIDC_CONSENT_GRANTED`, `OIDC_CONSENT_DENIED`, `OIDC_TOKENS_ISSUED`, `OIDC_TOKENS_REFRESHED`, `OIDC_CODE_EXCHANGE_FAILED`, `OIDC_CODE_REPLAY`, `OIDC_REFRESH_FAILED`, `OIDC_TOKEN_REVOKED`, `OIDC_CLIENT_CREATED`, `OIDC_CLIENT_DELETED`, `OIDC_ERROR` |

Requests without a specific event (e.g. a plain `GET`) have `event: null`.

---

## 9. OpenID Connect

| | Method | Path | Purpose |
|---|---|---|---|
| 🔓 | GET | `/.well-known/openid-configuration` | Discovery (issuer root) |
| 🔓 | GET | `/openid/.well-known/openid-configuration` | Discovery (alias) |
| 🔓 | GET | `/openid/jwks` | Public RS256 keys |
| 🔓 | GET | `/openid/authorize` | Browser entry point → consent page |
| 🔓 | GET | `/openid/consent` | Client + scope details for the consent screen |
| 🔑 | POST | `/openid/consent` | Approve / deny, returns `redirectTo` |
| 🔓* | POST | `/openid/token` | `authorization_code` and `refresh_token` grants |
| OIDC token | GET | `/openid/userinfo` | Claims for the granted scopes |
| 🔓* | POST | `/openid/revoke` | RFC 7009 revocation |
| 🛡️ | GET · POST · DELETE | `/openid/clients` · `/openid/clients/{id}` | Client registry (`read`/`create`/`delete:client`) |

\* client authentication: `client_id` (public) or client secret (confidential).

### Authorization request

```text
GET /api/v1/openid/authorize
  ?response_type=code
  &client_id=secureaccess-demo
  &redirect_uri=http://localhost:4000/oauth/callback.html
  &scope=openid%20profile%20email%20offline_access
  &state=Xy9…
  &nonce=Qm2…
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

→ `302 /oauth/consent.html?…` → after approval the browser lands on
`http://localhost:4000/oauth/callback.html?code=…&state=Xy9…&iss=http://localhost:4000`

### Token exchange

```bash
curl -X POST http://localhost:4000/api/v1/openid/token \
  -d grant_type=authorization_code \
  -d code=THE_CODE \
  -d redirect_uri=http://localhost:4000/oauth/callback.html \
  -d client_id=secureaccess-demo \
  -d code_verifier=THE_VERIFIER
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6…",
  "token_type": "Bearer",
  "expires_in": 900,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6…",
  "scope": "openid profile email offline_access",
  "refresh_token": "…"
}
```

Decoded `id_token` payload:

```json
{
  "iss": "http://localhost:4000", "sub": "…", "aud": "secureaccess-demo",
  "iat": 1789500000, "exp": 1789503600, "auth_time": 1789499950,
  "nonce": "Qm2…", "sid": "…",
  "name": "Jane Doe", "given_name": "Jane", "family_name": "Doe",
  "email": "jane@example.com", "email_verified": false
}
```

Confidential clients authenticate with HTTP Basic: `curl -u CLIENT_ID:CLIENT_SECRET …`.

### Register a client

```json
POST /api/v1/openid/clients
{ "name": "My SPA", "redirectUris": ["https://app.example.com/callback"], "isConfidential": false }
```

`201` → `{ id, clientId, name, redirectUris, isConfidential, hasSecret, createdAt, clientSecret? }` — `clientSecret` appears only once, for confidential clients.

---

## 10. System

| | Method | Path | Returns |
|---|---|---|---|
| 🔓 | GET | `/health` | `200 { status: "ok", database: "up", version, uptimeSeconds, timestamp }` or `503` |
| 🔓 | GET | `/api/v1` | Links to docs, spec, health, console, discovery |
| 🔓 | GET | `/swagger.json` | OpenAPI 3.0 document |
| 🔓 | GET | `/api-docs/` | Swagger UI (`/api-docs` redirects here; static assets also at `/swagger-ui-assets/`) |
| 🔓 | GET | `/` | Interactive console |

---

## 11. Error catalogue

| HTTP | `error` | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | Body, query or path parameter failed validation (`details` has field messages) |
| 400 | `INVALID_JSON` | Malformed JSON body |
| 400 | `WEAK_PASSWORD` | Password rules not met |
| 400 | `PASSWORD_REUSE` | New password equals the current one |
| 400 | `MFA_NOT_INITIALIZED` · `MFA_NOT_ENABLED` · `INVALID_MFA_CODE` | MFA state/code problems |
| 400 | `CANNOT_MODIFY_SELF` | Admin tried to deactivate/delete themselves |
| 401 | `ACCESS_TOKEN_REQUIRED` | No `Authorization: Bearer` header |
| 401 | `INVALID_TOKEN` | JWT invalid, expired, wrong type or algorithm |
| 401 | `SESSION_REVOKED` | Session signed out, revoked or expired |
| 401 | `INVALID_ACCOUNT` | Account deactivated after the token was issued |
| 401 | `INVALID_CREDENTIALS` | Wrong email/password (or current password) |
| 401 | `INVALID_MFA` · `INVALID_MFA_TOKEN` | Wrong/replayed code · expired or foreign MFA token |
| 401 | `INVALID_REFRESH_TOKEN` · `REFRESH_TOKEN_REUSED` | Refresh failures |
| 403 | `FORBIDDEN` | Missing permission (`message` names it) |
| 403 | `ACCOUNT_DISABLED` | Correct password, deactivated account |
| 403 | `PROTECTED_ACCOUNT` | Change attempted on a protected demo account |
| 403 | `SYSTEM_ROLE` | Renaming, re-permissioning or deleting a system role |
| 404 | `NOT_FOUND` · `USER_NOT_FOUND` · `ROLE_NOT_FOUND` · `ROLE_NOT_ASSIGNED` · `DEVICE_NOT_FOUND` · `SESSION_NOT_FOUND` · `CLIENT_NOT_FOUND` | Missing resources |
| 409 | `EMAIL_EXISTS` · `ROLE_EXISTS` · `ROLE_NAME_TAKEN` · `MFA_ALREADY_ENABLED` · `LAST_ADMIN` · `CONFLICT` | Conflicts |
| 413 | `PAYLOAD_TOO_LARGE` | Body over 100 kb |
| 423 | `ACCOUNT_LOCKED` | Too many failures (`details.lockedUntil`) |
| 429 | `RATE_LIMITED` | Rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Unexpected error — quote the `requestId` |

OAuth endpoints (`/openid/authorize`, `/consent`, `/token`, `/userinfo`, `/revoke`) use RFC codes: `invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `unsupported_response_type`, `invalid_scope`, `access_denied`, `invalid_token`, `insufficient_scope`.

---

## 12. End-to-end curl walkthrough

Copy these one at a time. They need `node` only to pull fields out of JSON.

```bash
BASE=http://localhost:4000/api/v1   # or https://secure-access-a8j6fkex8-ramraghuls-projects.vercel.app/api/v1 for the live deployment
json() { node -pe "JSON.parse(require('fs').readFileSync(0)).$1"; }
```

```bash
# 1. Register
curl -s -X POST $BASE/auth/register -H "Content-Type: application/json" \
  -d '{"email":"walkthrough@example.com","password":"Str0ng!Passphrase","firstName":"Walk","lastName":"Through"}'
```

```bash
# 2. Log in and keep both tokens
LOGIN=$(curl -s -X POST $BASE/auth/login -H "Content-Type: application/json" \
  -d '{"email":"walkthrough@example.com","password":"Str0ng!Passphrase"}')
ACCESS=$(echo "$LOGIN" | json accessToken); REFRESH=$(echo "$LOGIN" | json refreshToken)
```

```bash
# 3. Call a protected endpoint
curl -s $BASE/auth/me -H "Authorization: Bearer $ACCESS"
```

```bash
# 4. Rotate the refresh token
NEW=$(curl -s -X POST $BASE/auth/refresh -H "Content-Type: application/json" -d "{\"refreshToken\":\"$REFRESH\"}")
echo "$NEW"
```

```bash
# 5. Replay the OLD refresh token → 401 REFRESH_TOKEN_REUSED, session revoked
curl -s -X POST $BASE/auth/refresh -H "Content-Type: application/json" -d "{\"refreshToken\":\"$REFRESH\"}"
```

```bash
# 6. The new access token no longer works either → 401 SESSION_REVOKED
curl -s $BASE/auth/me -H "Authorization: Bearer $(echo "$NEW" | json accessToken)"
```

```bash
# 7. A regular user cannot list users → 403 FORBIDDEN
ACCESS=$(curl -s -X POST $BASE/auth/login -H "Content-Type: application/json" \
  -d '{"email":"walkthrough@example.com","password":"Str0ng!Passphrase"}' | json accessToken)
curl -s $BASE/users -H "Authorization: Bearer $ACCESS"
```
