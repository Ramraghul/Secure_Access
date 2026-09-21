# Testing Guide

SecureAccess has **216 automated tests**: 100 fast unit tests and 116 integration tests that drive the real Express app against a real PostgreSQL database. Every pull request runs them in GitHub Actions.

Current coverage (`npm run test:coverage`): **93% statements · 77% branches · 95% functions · 94% lines**.

## Contents

1. [Quick start](#1-quick-start)
2. [How the suite is organised](#2-how-the-suite-is-organised)
3. [What is covered](#3-what-is-covered)
4. [How integration tests run](#4-how-integration-tests-run)
5. [Continuous integration](#5-continuous-integration)
6. [Writing a new test](#6-writing-a-new-test)
7. [Manual end-to-end testing](#7-manual-end-to-end-testing)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Quick start

```bash
docker compose up -d db
```

```bash
npm test
```

That's all. The Docker container exposes PostgreSQL on port **5433** and creates both `secureaccess` and `secureaccess_test` on first start. `.env.test` already points at the test database.

| Command | Runs |
|---|---|
| `npm test` | everything (unit + integration), serially |
| `npm run test:unit` | unit tests only — no database needed |
| `npm run test:integration` | integration tests only |
| `npm run test:coverage` | everything, with a coverage report in `coverage/` |
| `npm run typecheck` | TypeScript across `src/`, `tests/` and `scripts/` |

<details>
<summary>No Docker? Use any PostgreSQL</summary>

Create a database whose name contains `test`, then point the tests at it:

```bash
createdb secureaccess_test
```

```bash
DATABASE_URL="postgresql://USER:PASS@localhost:5432/secureaccess_test" npm test
```

</details>

---

## 2. How the suite is organised

```mermaid
flowchart TB
    subgraph Unit["Unit — tests/unit (no I/O, ~10 s)"]
        U1[password] --- U2[mfa] --- U3[jwt] --- U4[crypto / PKCE]
        U5[mask] --- U6[permissions] --- U7[validation] --- U8[helpers] --- U9[error handler]
    end
    subgraph Integration["Integration — tests/integration (real HTTP + PostgreSQL, ~35 s)"]
        I1[auth] --- I2[mfa] --- I3[users] --- I4[roles]
        I5[devices] --- I6[audit] --- I7[openid] --- I8[app & docs]
    end
    Unit --> Integration
```

```text
tests/
├── setup/
│   ├── env.ts              # sets NODE_ENV=test before each file (config then loads .env.test)
│   └── global-setup.ts     # once per run: guard DB name → prisma migrate reset → seed
├── unit/                   # pure functions
└── integration/
    ├── helpers.ts          # supertest client, user/session factories, TOTP helpers
    └── *.test.ts
```

Jest is configured with two **projects** (`jest.config.js`) so unit tests never need a database, and the database is reset only when integration tests are selected.

---

## 3. What is covered

### Unit tests

| File | Verifies |
|---|---|
| `password.test.ts` | Every strength rule (incl. the repeated-character rule), generated passwords are always strong and unique, bcrypt round-trip |
| `mfa.test.ts` | Secret/QR/otpauth generation, TOTP acceptance, ±1-step drift, replay rejection, backup-code normalisation and single use |
| `jwt.test.ts` | Round-trip, 15-minute TTL, token-type separation, tampering, wrong secret / `HS256` / wrong issuer / `alg: none`, expiry |
| `crypto.test.ts` | Random tokens, SHA-256 vector, constant-time compare, **RFC 7636 PKCE test vector**, `plain` rejected, refresh-token parsing |
| `mask.test.ts` | Deep, case-insensitive masking, OAuth artefacts, circular references, snippet truncation |
| `permissions.test.ts` | Exact grants, `manage` and `*` wildcards, no leakage between actions/resources |
| `validation.test.ts` | Normalisation, 400 error shape, refinements, role/permission rules, query coercion, PKCE format, redirect-URI safety (`//evil`, `javascript:`, fragments) |
| `helpers.test.ts` | CSV formula-injection escaping, private-IP detection, OIDC redirect building and scope-based claims |
| `device-trust.test.ts` | Trust is active only while set and unexpired, legacy trust without an expiry is ignored, 30-day default |
| `error-middleware.test.ts` | Error → HTTP mapping: AppError, Zod, Prisma (`P2025`, `P2002`, `P2003`, missing table/column → `503 SCHEMA_OUT_OF_DATE`), body-parser errors, generic 500 without leaks, full-path 404s |

### Integration tests

| File | Scenarios |
|---|---|
| `auth.test.ts` | Register (default role, weak password, duplicates, malformed JSON) · login (tokens, no enumeration, lockout after 5, counter reset, deactivated) · `/me` · profile update · refresh rotation · **refresh-token reuse revokes the session** · logout vs logout-all · list/revoke sessions and ownership · change password signs out other sessions · protected demo accounts |
| `mfa.test.ts` | Enrolment (hashed backup codes, wrong code, re-enrol refused) · 202 + `mfaToken` · two-step and single-step login · wrong code counts toward lockout · **TOTP replay rejected** · backup code works once · MFA token bound to device · access token rejected as MFA token · **code asked on every login unless the device is remembered** · remembered device skips MFA (`mfa: trusted_device`) until trust is revoked or expires · password change forgets devices · **regression: trusting a device without a code is refused** · disable requires password + code |
| `users.test.ts` | 401/403 boundaries, auditor read-only · search, status filter, pagination · no secrets in responses · deactivate revokes sessions · activate clears lockout · no self-deactivation/deletion · protected accounts · temporary password flow · delete |
| `roles.test.ts` | System roles seeded · create with de-duplication · validation · rename + replace permissions · system-role guard · delete · **assigning a role changes access on the next request** · `*` wildcard · last-admin guard · 404s |
| `devices.test.ts` | One device per browser · current device · trusting needs MFA + a current code and lasts 30 days · untrust · removing a device signs out its sessions · other users' devices are 404 · id validation |
| `audit.test.ts` | Login success/failure rows with the right user and event · anonymous failures · unauthenticated requests audited · **passwords, tokens, MFA secrets and backup codes never stored** · list filters · email search · sensitive filter · statistics · CSV export · purge · auditor vs user permissions |
| `openid.test.ts` | Discovery (root + alias) · JWKS importable · authorize redirects, never redirects to unknown clients/URIs, errors returned to client · consent details, auth required, denial · **full code + PKCE flow with id_token verified against JWKS** · first-party vs OIDC tokens isolated · scope-based claims · wrong verifier/redirect · expired code · **code replay revokes issued tokens** · refresh rotation and reuse · revocation · OIDC sessions listed · grant validation · confidential client with HTTP Basic · client permissions |
| `app.test.ts` | Health with DB + migration check · no pending migrations · API index · JSON 404 · security headers · CORS preflight · console pages served · **OpenAPI document is valid** · **every Express route is documented in the spec** · `/api-docs` → `/api-docs/` redirect · Swagger UI assets served locally with the spec embedded |

The "every route is documented" test walks the Express routers and fails if someone adds an endpoint without describing it in `src/swagger/openapi.ts`, so the docs cannot drift from the code.

---

## 4. How integration tests run

```mermaid
sequenceDiagram
    autonumber
    participant J as Jest
    participant G as global-setup.ts
    participant P as prisma migrate reset
    participant DB as secureaccess_test
    participant T as test file
    participant APP as Express app (in-process)

    J->>G: once, before integration tests
    G->>G: load .env.test, refuse DB names without "test"
    G->>P: drop schema, apply all migrations
    P->>DB: fresh tables
    G->>DB: seed roles, admin, demo accounts, demo OIDC client
    loop each test file (serially)
        J->>T: run
        T->>APP: supertest request (random port)
        APP->>DB: real queries
        T->>DB: direct Prisma assertions where useful
        T->>T: afterAll: flush pending audit writes, disconnect
    end
```

**Design decisions**

- **Real database, no mocks.** Transactions, unique constraints, cascades and conditional updates (which provide replay and race protection) are exactly what needs testing.
- **Migrations, not `db push`.** The reset applies the real migration files, so a broken migration fails CI before it reaches production.
- **Safety guard.** `global-setup.ts` refuses to reset any database whose name does not contain `test`.
- **Hermetic configuration.** `.env.test` pins every setting (token TTL, lockout, rate limiting off, bcrypt cost 4 for speed), so a developer's own `.env` cannot change results.
- **Isolation without truncation.** Every test creates users with unique emails, so files never interfere and nothing needs cleaning between them.
- **Deterministic async work.** Audit rows are written after responses; tests call `flushAuditLogs()` before asserting on them.
- **Stable OIDC issuer.** supertest uses a random port per request, so OpenID tests pin the `Host` header.
- **TOTP replay protection in tests.** `freshTotp()` clears the last-used step so several MFA logins can happen within one 30-second window; the replay test deliberately does not use it.

---

## 5. Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull request:

```mermaid
flowchart LR
    A[checkout] --> B[setup Node 22 + npm cache]
    B --> C[npm ci]
    C --> D[npm run typecheck]
    D --> E["npm run test:coverage<br/>PostgreSQL 16 service container"]
    E --> F[npm run build]
```

The workflow sets `DATABASE_URL` for the service container, which takes precedence over `.env.test`. GitHub Actions is free for public repositories.

---

## 6. Writing a new test

```ts
import { api, bearer, closeAll, createUserSession, loginAdmin } from "./helpers";

afterAll(closeAll);

it("lets an admin read a user", async () => {
  const admin = await loginAdmin();
  const user  = await createUserSession();

  const res = await api().get(`/api/v1/users/${user.userId}`).set(bearer(admin.accessToken));

  expect(res.status).toBe(200);
  expect(res.body.email).toBe(user.email);
});
```

| Helper | Returns |
|---|---|
| `api()` | a supertest agent for the in-process app |
| `registerUser(overrides?)` | `{ email, password, userId }` |
| `createUserSession()` | registered + logged-in `{ email, password, userId, accessToken, refreshToken }` |
| `loginAdmin()` / `loginDemo("auditor" \| "user")` | sessions for seeded accounts |
| `login(email, password, extra?, userAgent?)` | raw login response |
| `enableMfa(session)` | `{ secret, backupCodes }` after full enrolment |
| `totpCode(secret)` / `freshTotp(userId, secret)` | a current TOTP code (the latter clears replay state) |
| `bearer(token)` | `{ Authorization: "Bearer …" }` |
| `prisma` | direct database access for assertions |
| `closeAll()` | flush audit writes and disconnect — call in `afterAll` |

---

## 7. Manual end-to-end testing

### With the console

1. `npm run dev` → open `http://localhost:4000/`.
2. Sign in with `auditor@secureaccess.dev` / `Auditor!Demo#2026` and browse Users, Roles and Audit — watch the Request log.
3. Register a new account, enable MFA with an authenticator app, sign out, sign in again and complete the MFA step.
4. **OpenID Connect** tab → run the demo sign-in and check that every step on the callback page is ticked.
5. Sign in as the local admin (`admin@secureaccess.dev` / `ChangeMe!Local#2026`), create a role, assign it to your new user, and confirm their tabs change after a refresh.

### With Swagger UI

1. Open `/api-docs`.
2. Run **POST /api/v1/auth/login** with a demo account and copy `accessToken`.
3. Click **Authorize**, paste the token, and try any endpoint.

### With curl

```bash
BASE=http://localhost:4000/api/v1
TOKEN=$(curl -s -X POST $BASE/auth/login -H "Content-Type: application/json" \
  -d '{"email":"auditor@secureaccess.dev","password":"Auditor!Demo#2026"}' | node -pe "JSON.parse(require('fs').readFileSync(0)).accessToken")
curl -s $BASE/auth/me -H "Authorization: Bearer $TOKEN"
```

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `Can't reach database server at localhost:5433` | `docker compose up -d db`, or set `DATABASE_URL` to your PostgreSQL |
| `database "secureaccess_test" does not exist` | The Docker volume predates `docker/postgres-init.sql`: `docker compose exec db createdb -U postgres secureaccess_test` |
| `Refusing to reset database ...` | The test database name must contain `test` |
| Tests hang after finishing | A new test file is missing `afterAll(closeAll)` |
| MFA test flaky around a 30-second boundary | Use `freshTotp()` for codes that do not test replay behaviour |
| OpenAPI coverage test fails | Document the new route in `src/swagger/openapi.ts` |
