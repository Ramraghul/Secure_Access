# Deployment Guide (Free Tier)

SecureAccess needs two things in production: **a Node.js web service** and **a PostgreSQL database**.
Both are available for free. This guide covers the recommended setup step by step, then the alternatives.

## Contents

1. [Choosing a free stack](#1-choosing-a-free-stack)
2. [Prepare secrets](#2-prepare-secrets)
3. [Database: Neon (recommended)](#3-database-neon)
4. [Web service: Render (recommended)](#4-web-service-render)
5. [Alternative: Vercel](#5-alternative-vercel)
6. [Alternative: Docker hosts](#6-alternative-docker-hosts)
7. [Upgrading an existing v2 database](#7-upgrading-an-existing-v2-database)
8. [Post-deploy checklist](#8-post-deploy-checklist)
9. [Environment variable reference](#9-environment-variable-reference)
10. [Staying inside free limits](#10-staying-inside-free-limits)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Choosing a free stack

```mermaid
flowchart LR
    GH[GitHub repo] -->|push to main| CI[GitHub Actions<br/>typecheck · tests · build]
    GH -->|auto deploy| RENDER[Render free web service<br/>Node 22]
    RENDER -->|DATABASE_URL, TLS| NEON[(Neon free PostgreSQL)]
    USER([Visitors]) -->|HTTPS| RENDER
```

| Option | Web service | Database | Good for | Watch out for |
|---|---|---|---|---|
| **Recommended** | Render free | Neon free | Everything works as designed: one long-running process, rate limiting, audit writes, OIDC keys | Render sleeps after 15 min idle — first request takes ~30–60 s |
| Existing setup | Vercel hobby | Supabase free | Already deployed there | Serverless: rate limits are per instance; set `OIDC_PRIVATE_KEY` or OIDC tokens break between invocations; Supabase pauses after 7 days without activity |
| Containers | Koyeb / Fly.io / Railway trial | Neon or Supabase | Uses the included `Dockerfile` | Free allowances change often — check current limits |

Everything below costs nothing and needs no credit card for Render + Neon at the time of writing.

---

## 2. Prepare secrets

Run these locally and keep the output somewhere safe (a password manager).

```bash
# 1) JWT signing secret (any 32+ character random string)
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

```bash
# 2) RSA key for OpenID Connect tokens (prints OIDC_PRIVATE_KEY=...)
npm run keys:generate
```

```text
# 3) Pick a strong private admin password, e.g.
SEED_ADMIN_PASSWORD=<16+ chars, upper, lower, digit, symbol, no common words>
```

> Never commit these values. `.env` and `keys/` are git-ignored.

---

## 3. Database: Neon

1. Sign up at [neon.tech](https://neon.tech) and create a project (choose the region closest to your Render region).
2. Open **Connection Details** and copy the connection string. Use the **direct** (non-pooled) string — it works for both the app and migrations at portfolio traffic levels.
3. Make sure it ends with `?sslmode=require`:

   ```text
   postgresql://USER:PASSWORD@ep-xxxx.region.aws.neon.tech/neondb?sslmode=require
   ```

4. That's it — tables are created by the deploy step (`prisma migrate deploy`).

<details>
<summary>Using Supabase instead</summary>

1. Create a project at [supabase.com](https://supabase.com) → **Project Settings → Database**.
2. Copy the **Session mode / direct** connection string (port 5432), replace `[YOUR-PASSWORD]`, and append `?sslmode=require`.
3. Free projects pause after a week without traffic; resume them from the dashboard.

</details>

---

## 4. Web service: Render

### Option A — Blueprint (uses `render.yaml`)

1. Push the repository to GitHub.
2. In Render: **New → Blueprint** → pick the repository. Render reads `render.yaml`.
3. Fill in the values marked "sync: false":

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | Neon connection string |
   | `OIDC_PRIVATE_KEY` | output of `npm run keys:generate` (without the `OIDC_PRIVATE_KEY=` prefix) |
   | `SEED_ADMIN_PASSWORD` | your private admin password |
   | `PUBLIC_URL` | leave empty for the first deploy |

   `JWT_SECRET` is generated automatically.
4. Click **Apply**. The first build takes a few minutes.
5. Copy the service URL (e.g. `https://secureaccess.onrender.com`), set `PUBLIC_URL` to it, and let Render redeploy.

### Option B — Manual web service

| Setting | Value |
|---|---|
| Runtime | Node |
| Build command | `npm ci --include=dev && npm run build && npx prisma migrate deploy && npm run seed:prod` |
| Start command | `npm start` |
| Health check path | `/health` |
| Instance type | Free |
| Environment | the variables from the table above, plus `NODE_ENV=production`, `NODE_VERSION=22`, `JWT_SECRET` |

### What happens on every deploy

```mermaid
flowchart TD
    P[git push main] --> I["npm ci --include=dev<br/>(runs prisma generate)"]
    I --> B["npm run build<br/>tsc → dist/"]
    B --> M["prisma migrate deploy<br/>applies only new migrations"]
    M --> S["npm run seed:prod<br/>idempotent: roles, admin (first time), demo accounts, demo OIDC client"]
    S --> ST[npm start → node dist/server.js]
    ST --> H{GET /health = 200?}
    H -- yes --> LIVE([Traffic switches to the new version])
    H -- no --> OLD([Previous version keeps serving])
```

- `--include=dev` is needed because `NODE_ENV=production` would otherwise skip TypeScript.
- Migrations and the seed are safe to run on every deploy: nothing is duplicated, existing admins are never changed.
- If `SEED_ADMIN_PASSWORD` is not set in production, the seed generates one and prints it **once** in the build log.

---

## 5. Alternative: Vercel

**➡ Full step-by-step guide with diagrams: [VERCEL.md](VERCEL.md)** — choosing the database connection (Supabase session pooler / Neon), environment variables, the build pipeline, updating the existing v2 deployment, how Swagger UI is bundled, preview deployments and troubleshooting.

Short version:

1. Import the repository in Vercel (Framework preset: **Other**).
2. Add environment variables: `DATABASE_URL`, `JWT_SECRET`, `OIDC_PRIVATE_KEY` (**required** on Vercel), `SEED_ADMIN_PASSWORD`, `PUBLIC_URL` (your `*.vercel.app` URL), `NODE_ENV=production`, `AUDIT_LOG_READS=false`.
3. Deploy. The `vercel-build` script runs `prisma generate`, `prisma migrate deploy` and the seed.

**How the code adapts to serverless**

| Concern | Handling |
|---|---|
| No long-running listener | `server.ts` only calls `listen()` when `VERCEL` is not set |
| Audit rows written after the response | `waitUntil()` from `@vercel/functions` keeps the function alive until the insert finishes |
| Read-only filesystem | File logging switches to `/tmp/logs` (or set `LOG_TO_FILE=false`) |
| Swagger UI assets | Served from `node_modules/swagger-ui-dist` via a literal `__dirname` path that Vercel's file tracer bundles (also listed in `includeFiles`); `/api-docs` redirects to `/api-docs/` so relative asset URLs resolve |
| Static console | `vercel.json` includes `public/**` in the function bundle |
| Schema drift | `/health` reports pending migrations; missing-column errors return `503 SCHEMA_OUT_OF_DATE` |

**Limits to accept:** rate-limit counters live in memory per function instance, and cold starts add latency.

---

## 6. Alternative: Docker hosts

The `Dockerfile` builds a small production image that runs as a non-root user, applies migrations, seeds, and starts the server.

```bash
docker build -t secureaccess .
```

```bash
docker run -p 4000:4000 \
  -e DATABASE_URL="postgresql://...?...sslmode=require" \
  -e JWT_SECRET="..." \
  -e OIDC_PRIVATE_KEY="..." \
  -e SEED_ADMIN_PASSWORD="..." \
  -e PUBLIC_URL="https://your-domain" \
  secureaccess
```

Run the whole stack locally (API + PostgreSQL):

```bash
docker compose --profile app up -d --build
```

---

## 7. Upgrading an existing v2 database

Version 2 was deployed with the migration `20260419151117_update_secure`. Version 3 adds one migration, `20260915000000_sessions_oidc_lockout`, which only **adds** columns and tables — no data is dropped.

```mermaid
flowchart TD
    Q{Does the database have a<br/>_prisma_migrations table listing<br/>20260419151117_update_secure?}
    Q -- yes --> D[npx prisma migrate deploy]
    Q -- "no (created with db push)" --> R["npx prisma migrate resolve --applied 20260419151117_update_secure"]
    R --> D
    D --> S[npm run seed / seed:prod]
    S --> DONE([v3 schema ready])
```

Check which case applies:

```bash
npx prisma migrate status
```

After upgrading:

- Existing users keep their passwords. Old v2 JWTs stop working (the token format changed) — everyone signs in again.
- The v2 admin (`admin@secureaccess.ca`) keeps its account. To keep using it as the seeded admin, set `SEED_ADMIN_EMAIL=admin@secureaccess.ca`; the seed makes sure it has the `admin` role.
- Devices that v2 automatically marked as trusted remain trusted. To force MFA on all devices, run `UPDATE devices SET "isTrusted" = false;`.
- The RSA key that v2 committed to `keys/` is no longer used. Generate a new one with `npm run keys:generate`.

---

## 8. Post-deploy checklist

| Check | Expected |
|---|---|
| `GET /health` | `{"status":"ok","database":"up","migrations":"up-to-date",...}` |
| `/` | Console loads; the header pill shows "API online" |
| `/api-docs/` | Swagger UI loads and "Try it out" calls your deployment |
| Sign in with `auditor@secureaccess.dev` / `Auditor!Demo#2026` | Users, Roles and Audit tabs visible, modifications refused |
| OpenID Connect tab → demo sign-in | Callback page shows all steps ticked |
| `/.well-known/openid-configuration` | `issuer` equals your `PUBLIC_URL` |
| Sign in as your admin | Works with `SEED_ADMIN_PASSWORD` |

For a portfolio, share the console URL and the two demo accounts. Keep the admin credentials private.

---

## 9. Environment variable reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | ✅ | — | PostgreSQL connection string |
| `JWT_SECRET` | ✅ | — | 32+ chars, signs first-party access tokens (HS512) |
| `NODE_ENV` | | `development` | `production` in deployments |
| `PORT` | | `4000` | Render/Docker set this automatically |
| `PUBLIC_URL` | recommended | derived from request | Base URL, used as OIDC issuer; enables CSP `upgrade-insecure-requests` when https |
| `LOCAL_URL` | | `http://localhost:<PORT>` | *Local* entry in Swagger's Servers dropdown |
| `DEPLOYED_URL` | | `https://secure-access-a8j6fkex8-ramraghuls-projects.vercel.app` | *Deployed* entry in Swagger's Servers dropdown |
| `TRUST_PROXY` | | `1` | Number of proxies in front of the app |
| `OIDC_PRIVATE_KEY` | recommended (required on Vercel) | ephemeral key | RSA key (PEM or base64 PEM) for RS256 OIDC tokens |
| `JWT_EXPIRES_IN` | | `15m` | Access token lifetime |
| `REFRESH_TOKEN_TTL_DAYS` | | `7` | Session / refresh token lifetime |
| `BCRYPT_ROUNDS` | | `12` | Password hashing cost |
| `MAX_FAILED_LOGINS` | | `5` | Attempts before lockout |
| `LOCKOUT_MINUTES` | | `15` | Lockout duration |
| `TRUSTED_DEVICE_DAYS` | | `30` | How long "remember this device" skips the MFA code |
| `RATE_LIMIT_ENABLED` | | `true` | Disable only for tests |
| `RATE_LIMIT_WINDOW_MS` | | `900000` | Rate-limit window |
| `RATE_LIMIT_MAX` | | `300` | Requests per IP per window (all API routes) |
| `RATE_LIMIT_AUTH_MAX` | | `20` | Failed credential attempts per IP per window |
| `ALLOWED_ORIGINS` | | `*` | Comma-separated CORS origins |
| `AUDIT_LOG_READS` | | `true` | `false` skips GET requests in the audit log |
| `AUDIT_RETENTION_DAYS` | | `90` | Default age for `POST /audit/purge` |
| `LOG_LEVEL` | | `info` (`debug` in dev) | Winston level |
| `LOG_TO_FILE` | | enabled when writable | `false` for container/serverless hosts |
| `SEED_ADMIN_EMAIL` | | `admin@secureaccess.dev` | Admin created by the seed |
| `SEED_ADMIN_PASSWORD` | recommended | dev default / generated in production | Admin password on first seed |
| `SEED_DEMO_ACCOUNTS` | | `true` | Create the protected demo accounts |

---

## 10. Staying inside free limits

| Resource | What uses it | How to keep it small |
|---|---|---|
| Database storage (Neon 0.5 GB) | `audit_logs` grows with every request | Set `AUDIT_LOG_READS=false`; purge old rows with `POST /api/v1/audit/purge` (admin) |
| Render instance hours (750 h/month) | One always-on service fits | Don't run several free services 24/7 |
| Cold starts | Render sleeps after 15 min | Optional: a free uptime monitor pinging `/health` every 10–14 min keeps it warm |
| Neon compute | Auto-suspends when idle | Nothing to do — first query after idle adds ~1 s |

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Build fails at `prisma migrate deploy` with P1001 | Database unreachable | Check `DATABASE_URL`, `sslmode=require`, Neon project not deleted |
| Build fails with `SEED_ADMIN_PASSWORD is too weak: …` | The admin password breaks a rule — often it contains `admin` | Pick one with 12+ chars, upper, lower, digit, symbol and none of `password` `123456` `qwerty` `admin` `letmein`, then redeploy |
| `Unknown argument …` (`PrismaClientValidationError`) | The running process loaded a Prisma Client generated from an older `schema.prisma` | `npx prisma generate`, then restart the server (`npm run dev` does both; deployments run `prisma generate` during the build) |
| `P3005 The database schema is not empty` | v2 DB created with `db push` | See [section 7](#7-upgrading-an-existing-v2-database) |
| `The column … does not exist`, `503 SCHEMA_OUT_OF_DATE`, or `/health` shows `migrations: pending` | Code deployed without running migrations | `npx prisma migrate deploy` against that database, then `npm run seed` |
| Startup error `JWT_SECRET must be at least 32 characters` | Short/missing secret | Set a longer value |
| OIDC demo: `id_token signature` step fails after redeploy | No `OIDC_PRIVATE_KEY`, key regenerated | Set `OIDC_PRIVATE_KEY` |
| OIDC demo: `redirect_uri is not registered` | `PUBLIC_URL` differs from the URL in the browser | Set `PUBLIC_URL` to the exact public origin (no trailing slash) |
| Swagger UI blank | Assets not bundled, or an old build without the trailing-slash redirect | Open `/api-docs/`; `/swagger-ui-assets/swagger-ui.css` must return 200 — see [VERCEL.md §11](VERCEL.md#11-how-swagger-ui-works-on-vercel) |
| `429 RATE_LIMITED` while testing | Rate limiter | Wait 15 min or raise `RATE_LIMIT_MAX` |
| Admin password unknown | Seed generated one | Find it in the first build log, or set `SEED_ADMIN_EMAIL` to a new address and redeploy |
